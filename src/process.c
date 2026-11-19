/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "process.h"
#include "io.h"
#include "pipeline.h"
#include "spsc.h"
#include "ui.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

/* Number of leading bytes scanned for NULs when deciding a file is binary;
 * covers the usual text/binary header region without reading the whole file. */
#define BINARY_SCAN_SIZE (JSTR_IO_KIB * 4)

/* --grep mode: print the whole content of every line that matches FIND.
 * Matching is line-based like grep (a regex can never span newlines here,
 * unlike the replace path which scans the whole buffer). */
/**
 * @brief Scan a buffer line-by-line and append grep output.
 *
 * @details This function is part of the process.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param t compiled fixed-string matcher.
 * @param buf growable byte buffer.
 * @param fname file name.
 * @param fname_len FNAME byte length.
 * @param find find string.
 * @param find_len FIND byte length.
 * @param out destination growable buffer.
 * @param matched_out receives whether any line matched.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B workers; far_compile is called by main or Stage C.
 */
static jstr_ret_ty
grep_scan_to_buf(const jstr_twoway_ty *R t, const jstr_ty *R buf,
                 const char *R fname, size_t fname_len,
                 const char *R find, size_t find_len,
                 jstr_ty *R out, int *R matched_out)
{
	*matched_out = 0;
	if (find_len == 0)
		return JSTR_RET_SUCC;
	const char *d = buf->data;
	const size_t n = buf->size;
	const char *p = d;
	for (size_t line = 1;; ++line) {
		const char *nl = memchr(p, '\n', (size_t)(d + n - p));
		const size_t line_len = (nl != NULL) ? (size_t)(nl - p) : (size_t)(d + n - p);
		const char *const line_data = line_len ? p : "";
		int matched = 0;
		size_t moff = 0;
		size_t mlen = 0;
		if (G.mode & MODE_USE_REGEX) {
			regmatch_t rm = { 0 };
			matched = (jstr_re_search_len(&G.regex, line_data, line_len, &rm, G.eflags) == JSTR_RE_RET_NOERROR);
			if (matched) {
				moff = (size_t)rm.rm_so;
				mlen = (size_t)(rm.rm_eo - rm.rm_so);
			}
		} else {
			const char *hit = (const char *)jstr_memmem_exec(t, p, line_len, find, find_len);
			if (hit != NULL) {
				matched = 1;
				moff = (size_t)(hit - p);
				mlen = find_len;
			}
		}
		if (matched) {
			*matched_out = 1;
			if (jstr_chk(ui_format_grep_line(out, fname, fname_len, line, line_data, line_len, moff, mlen)))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		}
		if (nl == NULL)
			break;
		p = nl + 1;
	}
	return JSTR_RET_SUCC;
}

/* --grep TUI: collect every matching line into G.grep_lines. */
/**
 * @brief Collect grep matches into the legacy global list.
 *
 * @details This function is part of the process.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param t compiled fixed-string matcher.
 * @param buf growable byte buffer.
 * @param fname file name.
 * @param fname_len FNAME byte length.
 * @param find find string.
 * @param find_len FIND byte length.
 * @param limit maximum number of emitted matches.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B workers; far_compile is called by main or Stage C.
 */
void
grep_collect_file_n(const jstr_twoway_ty *R t, const jstr_ty *R buf, const char *R fname,
                    size_t fname_len, const char *R find,
                    size_t find_len, size_t limit)
{
	const char *d = buf->data;
	const size_t n = buf->size;
	const char *p = d;
	for (size_t line = 1;; ++line) {
		const char *nl = memchr(p, '\n', (size_t)(d + n - p));
		const size_t line_len = (nl != NULL) ? (size_t)(nl - p) : (size_t)(d + n - p);
		const char *const line_data = line_len ? p : "";
		int matched = 0;
		size_t moff = 0;
		size_t mlen = 0;
		if (G.mode & MODE_USE_REGEX) {
			regmatch_t rm = { 0 };
			matched = (jstr_re_search_len(&G.regex, line_data, line_len, &rm, G.eflags) == JSTR_RE_RET_NOERROR);
			if (matched) {
				moff = (size_t)rm.rm_so;
				mlen = (size_t)(rm.rm_eo - rm.rm_so);
			}
		} else {
			const char *hit = (const char *)jstr_memmem_exec(t, p, line_len, find, find_len);
			if (hit != NULL) {
				matched = 1;
				moff = (size_t)(hit - p);
				mlen = find_len;
			}
		}
		if (matched) {
			G.grep_matched = 1;
			if (G.grep_lines.size >= G.grep_lines.cap) {
				G.grep_lines.cap = (G.grep_lines.cap == 0 ? 32 : G.grep_lines.cap * 2);
				grep_line_ty *const tmp = (grep_line_ty *)realloc(G.grep_lines.data, G.grep_lines.cap * sizeof(grep_line_ty));
				DIE_IF(!tmp, "%s", "Out of memory allocating grep results.\n");
				G.grep_lines.data = tmp;
			}
			G.grep_lines.data[G.grep_lines.size].fname = fname;
			G.grep_lines.data[G.grep_lines.size].fname_len = fname_len;
			G.grep_lines.data[G.grep_lines.size].line_num = line;
			G.grep_lines.data[G.grep_lines.size].content = line_data;
			G.grep_lines.data[G.grep_lines.size].content_len = line_len;
			G.grep_lines.data[G.grep_lines.size].match_off = moff;
			G.grep_lines.data[G.grep_lines.size].match_len = mlen;
			++G.grep_lines.size;
			if (G.grep_lines.size >= limit)
				return;
		}
		if (nl == NULL)
			break;
		p = nl + 1;
	}
}

/**
 * @brief Collect all grep matches from one buffer.
 *
 * @details This function is part of the process.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param t compiled fixed-string matcher.
 * @param buf growable byte buffer.
 * @param fname file name.
 * @param fname_len FNAME byte length.
 * @param find find string.
 * @param find_len FIND byte length.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B workers; far_compile is called by main or Stage C.
 */
void
grep_collect_file(const jstr_twoway_ty *R t, const jstr_ty *R buf, const char *R fname,
                  size_t fname_len, const char *R find, size_t find_len)
{
	grep_collect_file_n(t, buf, fname, fname_len, find, find_len, (size_t)-1);
}

/**
 * @brief Apply FIX/REPLACE to an in-memory buffer.
 *
 * @details This function is part of the process.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param t compiled fixed-string matcher.
 * @param buf growable byte buffer.
 * @param find find string.
 * @param find_len FIND byte length.
 * @param rplc replacement string.
 * @param rplc_len REPLACE byte length.
 * @param out_changed receives the replacement count.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B workers; far_compile is called by main or Stage C.
 */
static jstr_ret_ty
process_buffer_compute(const jstr_twoway_ty *R t, jstr_ty *R buf,
                       const char *R find, const size_t find_len,
                       const char *R rplc, const size_t rplc_len,
                       size_t *R out_changed)
{
	union u {
		size_t zu;
		jstr_re_off_ty d;
	} changed;
	if (G.mode & MODE_USE_REGEX) {
		if (buf->size && buf->data[buf->size - 1] == '\n') {
			buf->data[buf->size - 1] = '\0';
			--buf->size;
		}
		changed.d = jstr_re_rplcn_backref_len_exec_j(&G.regex, buf, rplc, rplc_len, G.eflags, JSTR_NMATCH_MAX, G.n);
		if (jstr_re_chk(changed.d))
			jstr_re_errdie(changed.d, &G.regex, "%s", "Regex replacement failed.\n");
		changed.zu = (size_t)changed.d;
	} else {
		changed.zu = jstr_rplcn_len_exec_j(t, buf, find, find_len, rplc, rplc_len, G.n);
		if (jstr_unlikely(changed.zu == (size_t)-1))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	if (buf->size && buf->data[buf->size - 1] != '\n')
		DIE_IF(jstr_chk(jstr_pushback_j(buf, '\n')), "%s", "Out of memory.\n");
	*out_changed = changed.zu;
	return JSTR_RET_SUCC;
}

/**
 * @brief Process one file job from Stage A.
 *
 * @details This function is part of the process.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param t compiled fixed-string matcher.
 * @param buf growable byte buffer.
 * @param fname file name.
 * @param fname_len FNAME byte length.
 * @param st file status.
 * @param find find string.
 * @param find_len FIND byte length.
 * @param rplc replacement string.
 * @param rplc_len REPLACE byte length.
 * @param res result object produced by Stage B.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B workers; far_compile is called by main or Stage C.
 */
jstr_ret_ty
process_job(const jstr_twoway_ty *R t, jstr_ty **R buf,
            const char *R fname, size_t fname_len,
            const struct stat *st, const char *R find,
            const size_t find_len, const char *R rplc,
            const size_t rplc_len, confirm_phase_ty confirm_phase,
            process_result_ty *R res)
{
	jstr_ty *tmp = NULL;
	memset(res, 0, sizeof *res);
	res->st = *st;
	const size_t file_size = (size_t)st->st_size;
	const int tty = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
	if (!(G.mode & MODE_USE_REGEX) && file_size < find_len &&
	    !((G.mode & (MODE_CONFIRM | MODE_GREP)) && tty))
		return JSTR_RET_SUCC;
	jstr_ty *b = *buf;
	if (b == NULL) {
		b = (jstr_ty *)malloc(sizeof *b);
		if (jstr_unlikely(!b))
			goto err;
		*b = (jstr_ty)JSTR_INIT;
		*buf = b;
	}
	jstr_empty_j(b);
	if (rplc_len > find_len && !(G.mode & MODE_USE_REGEX))
		if (jstr_chk(jstr_reserve_j(b, file_size + rplc_len - find_len + S_LEN("\n") + 1)))
			goto err;
	if (jstr_chk(jstr_io_readfile_len_j(b, fname, 0, file_size)))
		goto err;
	if (jstr_io_isbinary_atleast(b->data, file_size, BINARY_SCAN_SIZE))
		return JSTR_RET_SUCC;
	if (G.mode & MODE_GREP) {
		if (G.grep_collect) {
			res->out = b;
			*buf = NULL;
			return JSTR_RET_SUCC;
		}
		tmp = (jstr_ty *)malloc(sizeof *tmp);
		if (jstr_unlikely(!tmp))
			goto err;
		*tmp = (jstr_ty)JSTR_INIT;
		if (jstr_chk(grep_scan_to_buf(t, b, fname, fname_len, find, find_len, tmp, &res->matched)))
			goto err;
		if (res->matched) {
			res->out = tmp;
			tmp = NULL;
		}
		jstr_empty_j(b);
		goto out;
	}
	if (confirm_phase == CONFIRM_SCAN) {
		res->out = b;
		*buf = NULL;
		return JSTR_RET_SUCC;
	}
	size_t changed = 0;
	if (jstr_chk(process_buffer_compute(t, b, find, find_len, rplc, rplc_len, &changed)))
		goto err;
	if (G.output_mode == OUT_STDOUT) {
		res->out = b;
		*buf = NULL;
		return JSTR_RET_SUCC;
	}
	if (changed == 0) {
		jstr_empty_j(b);
		return JSTR_RET_SUCC;
	}
	if (G.output_mode == OUT_BACKUP) {
		if (jstr_chk(io_write_inplace_backup(b, fname, fname_len, st)))
			goto err;
	} else {
		io_write_inplace_temp(b, fname, fname_len);
	}
	res->report = 1;
	jstr_empty_j(b);
	return JSTR_RET_SUCC;
err:
	res->err = 1;
out:
	if (tmp != NULL) {
		jstr_free_j(tmp);
		free(tmp);
	}
	return JSTR_RET_SUCC;
}

/**
 * @brief Process the stdin job from Stage A.
 *
 * @details This function is part of the process.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param t compiled fixed-string matcher.
 * @param bufp parameter defined by the owning module contract.
 * @param find find string.
 * @param find_len FIND byte length.
 * @param rplc replacement string.
 * @param rplc_len REPLACE byte length.
 * @param res result object produced by Stage B.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B workers; far_compile is called by main or Stage C.
 */
static jstr_ret_ty
process_stdin_job(const jstr_twoway_ty *R t, jstr_ty **R bufp,
                  const char *R find, size_t find_len,
                  const char *R rplc, size_t rplc_len,
                  process_result_ty *R res)
{
	jstr_ty *tmp = NULL;
	memset(res, 0, sizeof *res);
	if (find_len == 0 && (G.mode & MODE_GREP))
		return JSTR_RET_SUCC;
	jstr_ty *b = *bufp;
	if (b == NULL) {
		b = (jstr_ty *)malloc(sizeof *b);
		if (jstr_unlikely(!b))
			goto err;
		*b = (jstr_ty)JSTR_INIT;
		*bufp = b;
	}
	jstr_empty_j(b);
	if (jstr_chk(jstr_io_readstdin_j(b)))
		goto err;
	if (G.mode & MODE_GREP) {
		tmp = (jstr_ty *)malloc(sizeof *tmp);
		if (jstr_unlikely(!tmp))
			goto err;
		*tmp = (jstr_ty)JSTR_INIT;
		if (jstr_chk(grep_scan_to_buf(t, b, NULL, 0, find, find_len, tmp, &res->matched)))
			goto err;
		if (res->matched) {
			res->out = tmp;
			tmp = NULL;
		}
		jstr_empty_j(b);
		goto out;
	}
	if (find_len != 0) {
		size_t changed = 0;
		if (jstr_chk(process_buffer_compute(t, b, find, find_len, rplc, rplc_len, &changed)))
			goto err;
	}
	res->out = b;
	*bufp = NULL;
	goto out;
err:
	res->err = 1;
out:
	if (tmp != NULL) {
		jstr_free_j(tmp);
		free(tmp);
	}
	return JSTR_RET_SUCC;
}

/**
 * @brief Process one cached pass-2 file job.
 *
 * @details This function is part of the process.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param t compiled fixed-string matcher.
 * @param bufp parameter defined by the owning module contract.
 * @param file parameter defined by the owning module contract.
 * @param find find string.
 * @param find_len FIND byte length.
 * @param rplc replacement string.
 * @param rplc_len REPLACE byte length.
 * @param res result object produced by Stage B.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B workers; far_compile is called by main or Stage C.
 */
static jstr_ret_ty
process_mem_job(const jstr_twoway_ty *R t, jstr_ty **R bufp,
                const file_ty *R file, const char *R find, size_t find_len,
                const char *R rplc, size_t rplc_len, process_result_ty *R res)
{
	memset(res, 0, sizeof *res);
	res->st.st_mode = file->st_mode;
	res->st.st_size = (off_t)file->content_size;
	const int borrowed = file->content.data != NULL;
	jstr_ty *b = borrowed ? (jstr_ty *)(void *)&file->content : *bufp;
	if (!borrowed) {
		if (b == NULL) {
			b = (jstr_ty *)malloc(sizeof *b);
			if (jstr_unlikely(!b))
				goto err;
			*b = (jstr_ty)JSTR_INIT;
			*bufp = b;
		}
		jstr_empty_j(b);
		if (jstr_chk(jstr_reserve_j(b, file->content_size)) ||
		    jstr_chk(jstr_io_readfile_len_j(b, file->fname, 0, file->content_size)))
			goto err;
	}
	size_t changed = 0;
	if (jstr_chk(process_buffer_compute(t, b, find, find_len, rplc, rplc_len, &changed)))
		goto err;
	if (changed == 0) {
		if (!borrowed)
			jstr_empty_j(b);
		goto out;
	}
	if (G.output_mode == OUT_BACKUP) {
		if (jstr_chk(io_write_inplace_backup(b, file->fname, file->fname_len, &res->st)))
			goto err;
	} else {
		io_write_inplace_temp(b, file->fname, file->fname_len);
	}
	res->report = 1;
	if (!borrowed)
		jstr_empty_j(b);
	goto out;
err:
	res->err = 1;
out:
	return JSTR_RET_SUCC;
}

/**
 * @brief Send the single logical EOS when root completion conditions hold.
 *
 * @details This function is part of the process.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param root per-root pipeline context.
 * @param worker zero-based B worker index.
 * @param grep_live parameter defined by the owning module contract.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B workers; far_compile is called by main or Stage C.
 */
static void
maybe_send_eos(root_ctx_ty *R root, size_t worker, int grep_live)
{
	if (!atomic_load_explicit(&root->eos_taken, memory_order_acquire))
		return;
	atomic_store_explicit(&root->phase, ROOT_DRAINING, memory_order_release);
	if (atomic_load_explicit(&root->workers_done, memory_order_acquire) < pipeline_worker_count())
		return;
	if (atomic_load_explicit(&root->jobs_done, memory_order_acquire) <
	    atomic_load_explicit(&root->total, memory_order_acquire))
		return;
	if (atomic_exchange_explicit(&root->eos_sent, true, memory_order_acq_rel))
		return;
	atomic_store_explicit(&root->phase, ROOT_EOS, memory_order_release);
	far_result_ty *const eos = (far_result_ty *)calloc(1, sizeof *eos);
	if (jstr_unlikely(!eos))
		jstr_errdie("%s", "Out of memory.\n");
	eos->kind = FAR_RES_EOS;
	eos->total = atomic_load_explicit(&root->total, memory_order_acquire);
	const int send_ret = grep_live ? pipeline_grep_work_send(worker, eos) : pipeline_done_send(worker, eos);
	if (send_ret != 0)
		free(eos);
}

/**
 * @brief Record one worker completion and test the EOS barrier.
 *
 * @details This function is part of the process.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param root per-root pipeline context.
 * @param worker zero-based B worker index.
 * @param grep_live parameter defined by the owning module contract.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B workers; far_compile is called by main or Stage C.
 */
static void
finish_worker(root_ctx_ty *R root, size_t worker, int grep_live)
{
	atomic_fetch_add_explicit(&root->workers_done, 1, memory_order_acq_rel);
	maybe_send_eos(root, worker, grep_live);
}

/**
 * @brief Stage-B worker loop.
 *
 * @details This function is part of the process.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param arg parameter defined by the owning module contract.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B workers; far_compile is called by main or Stage C.
 */
far_thread_ret_ty
process_thread(void *arg)
{
	const size_t worker = (size_t)(uintptr_t)arg;
	jstr_ty *buf = NULL;
	unsigned long seen_epoch = 0;
	for (;;) {
		root_ctx_ty *const root = pipeline_root_get();
		if (root == NULL) {
			if (pipeline_stopping())
				break;
			struct timespec ts = { 0, 1000000 };
			nanosleep(&ts, NULL);
			continue;
		}
		const unsigned long epoch = pipeline_root_epoch();
		if (pipeline_root_get() != root)
			continue;
		if (epoch == seen_epoch) {
			struct timespec ts = { 0, 1000000 };
			nanosleep(&ts, NULL);
			continue;
		}
		seen_epoch = epoch;
		unsigned int spin = 0;
		for (;;) {
			far_job_ty *const job = pipeline_work_try_recv();
			if (job != NULL)
				spin = 0;
			if (job == NULL) {
				if (atomic_load_explicit(&root->eos_taken, memory_order_acquire)) {
					const int grep_live = (G.mode & MODE_GREP) && G.grep_collect &&
					                      isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
					finish_worker(root, worker, grep_live);
					break;
				}
				spsc_backoff(&spin);
				continue;
			}
			if (job->kind == FAR_JOB_EOS) {
				atomic_store_explicit(&root->eos_taken, true, memory_order_release);
				const int grep_live = (G.mode & MODE_GREP) && G.grep_collect &&
				                      isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
				finish_worker(root, worker, grep_live);
				break;
			}
			far_result_ty *const res = (far_result_ty *)calloc(1, sizeof *res);
			if (jstr_unlikely(!res))
				jstr_errdie("%s", "Out of memory.\n");
			res->seq = job->seq;
			res->kind = FAR_RES_DATA;
			res->path = job->path;
			res->path_len = job->path_len;
			if (jstr_unlikely(atomic_load_explicit(&root->cancel, memory_order_acquire)))
				res->canceled = 1;
			else {
				switch (job->kind) {
				case FAR_JOB_FILE:
					process_job(job->root->t, &buf, job->path, job->path_len, &job->st,
					            job->root->a->find, job->root->a->find_len,
					            job->root->a->rplc, job->root->a->rplc_len,
					            job->root->a->confirm_phase, &res->pr);
					break;
				case FAR_JOB_STDIN:
					process_stdin_job(job->root->t, &buf, job->root->a->find,
					                  job->root->a->find_len, job->root->a->rplc,
					                  job->root->a->rplc_len, &res->pr);
					break;
				case FAR_JOB_MEM:
					process_mem_job(job->root->t, &buf, job->mem_file,
					                job->root->a->find, job->root->a->find_len,
					                job->root->a->rplc, job->root->a->rplc_len, &res->pr);
					break;
				default:
					res->pr.err = 1;
					break;
				}
				if (buf == NULL) {
					buf = (jstr_ty *)malloc(sizeof *buf);
					if (jstr_unlikely(!buf))
						jstr_errdie("%s", "Out of memory.\n");
					*buf = (jstr_ty)JSTR_INIT;
				}
			}
			free(job);
			const int grep_live = (G.mode & MODE_GREP) && G.grep_collect &&
			                      isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
			const int send_ret = grep_live ? pipeline_grep_work_send(worker, res) : pipeline_done_send(worker, res);
			if (send_ret != 0) {
				ui_result_free(res);
				atomic_fetch_add_explicit(&root->jobs_done, 1, memory_order_acq_rel);
				finish_worker(root, worker, grep_live);
				break;
			}
			atomic_fetch_add_explicit(&root->jobs_done, 1, memory_order_acq_rel);
			maybe_send_eos(root, worker, grep_live);
		}
	}
	if (buf != NULL)
		jstr_free_j(buf);
	free(buf);
	return FAR_THREAD_RETURN;
}

/* Compile FIND (regex or Two-Way fixed-string matcher) into the global
 * state. Recompiles when the regex mode/cflags change between files; the
 * MODE_COMPILED bit alone cannot guard that, since -R/-E/-F may appear
 * anywhere on the command line, even after a file argument. */
/**
 * @brief Compile or recompile the global find matcher.
 *
 * @details This function is part of the process.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param t compiled fixed-string matcher.
 * @param find find string.
 * @param find_len FIND byte length.
 * @param rplc replacement string.
 * @param rplc_len REPLACE byte length.
 * @param force_recompile parameter defined by the owning module contract.
 * @param err_buf parameter defined by the owning module contract.
 * @param err_size parameter defined by the owning module contract.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B workers; far_compile is called by main or Stage C.
 */
jstr_ret_ty
far_compile(jstr_twoway_ty *R t, const char *R find, size_t find_len, const char *R rplc, size_t rplc_len, int force_recompile, char *err_buf, size_t err_size)
{
	const int want_regex = (G.mode & MODE_USE_REGEX) != 0;
	if (force_recompile || !(G.mode & MODE_COMPILED) || want_regex != G.compiled_regex || (want_regex && G.cflags != G.compiled_cflags)) {
		if (G.mode & MODE_COMPILED) {
			if (G.compiled_regex)
				jstr_re_free(&G.regex);
			G.mode &= ~MODE_COMPILED;
		}
		if (want_regex) {
			if (find_len > 0) {
				const int ret = jstr_re_comp(&G.regex, find, G.cflags);
				if (jstr_unlikely(ret != JSTR_RE_RET_NOERROR)) {
					if (err_buf && err_size > 0)
						regerror(ret, &G.regex.reg, err_buf, err_size);
					return JSTR_RET_ERR;
				}
			}
			/* Validate backreferences */
			size_t max_backref = 0;
			for (size_t idx = 0; idx + 1 < rplc_len; ++idx) {
				if (rplc[idx] == '\\' && rplc[idx+1] >= '1' && rplc[idx+1] <= '9') {
					size_t num = rplc[idx+1] - '0';
					if (num > max_backref)
						max_backref = num;
					++idx;
				}
			}
			if (jstr_unlikely(max_backref > G.regex.reg.re_nsub)) {
				if (err_buf && err_size > 0)
					snprintf(err_buf, err_size, "Replace backreference \\%zu exceeds find capture groups (%zu)", max_backref, G.regex.reg.re_nsub);
				return JSTR_RET_ERR;
			}
		} else {
			jstr_memmem_comp(t, find, find_len);
		}
		G.compiled_regex = want_regex;
		G.compiled_cflags = G.cflags;
		G.mode |= MODE_COMPILED;
	}
	return JSTR_RET_SUCC;
}

