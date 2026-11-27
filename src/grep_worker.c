/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "grep_worker.h"
#include "io.h"
#include "pipeline.h"
#include "procfs.h"
#include "ui.h"
#include "spsc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define GREP_BATCH_MAX 64

typedef enum {
	CACHE_DISK_ONLY,
	CACHE_CACHED
} cache_state_ty;

typedef struct cached_file_ty {
	char *fname;
	size_t fname_len;
	size_t size;
	unsigned int mode;
	jstr_ty content;
	cache_state_ty state;
} cached_file_ty;

static _Thread_local size_t d_worker;
static _Thread_local cached_file_ty *cache;
static _Thread_local size_t cache_size;
static _Thread_local size_t cache_cap;
static _Thread_local size_t cache_bytes;
static _Thread_local size_t cache_max;

typedef struct grep_cfg_state_ty {
	unsigned long gen;
	char *find;
	size_t find_len;
	char *files;
	size_t files_len;
	char *include;
	size_t include_len;
	char *exclude;
	size_t exclude_len;
	size_t limit;
	int use_regex;
	int cflags;
	int eflags;
	jstr_twoway_ty twoway;
	jstr_re_ty regex;
	jstr_re_ty inc_re;
	jstr_re_ty exc_re;
	int have_inc;
	int have_exc;
	int ready;
} grep_cfg_state_ty;

static _Thread_local grep_cfg_state_ty C;
static _Thread_local size_t sent_matches;
static _Thread_local size_t data_seen;
static _Thread_local size_t pending_eos_total;
static _Thread_local int pending_eos;
static _Thread_local grep_line_ty batch[GREP_BATCH_MAX];
static _Thread_local size_t batch_n;
static _Thread_local size_t batch_files;
static _Thread_local unsigned long batch_gen;
static _Thread_local grep_lines_ty *retire_cur;
static _Thread_local size_t retire_at;

static void batch_discard(void);

/**
 * @anchor spec_cfg_clear
 * @brief Free all D-local configuration state.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static void
cfg_clear(void)
{
	free(C.find);
	free(C.files);
	free(C.include);
	free(C.exclude);
	if (C.use_regex)
		jstr_re_free(&C.regex);
	if (C.have_inc)
		jstr_re_free(&C.inc_re);
	if (C.have_exc)
		jstr_re_free(&C.exc_re);
	memset(&C, 0, sizeof C);
}

/**
 * @anchor spec_cfg_compile
 * @brief Install a new D configuration snapshot.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param msg owned message object.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static void
cfg_compile(grep_cfg_ty *R msg)
{
	batch_discard();
	cfg_clear();
	C.gen = msg->gen;
	C.find = msg->find;
	C.find_len = msg->find_len;
	C.files = msg->files;
	C.files_len = msg->files_len;
	C.include = msg->include;
	C.include_len = msg->include_len;
	C.exclude = msg->exclude;
	C.exclude_len = msg->exclude_len;
	C.limit = msg->limit;
	C.use_regex = msg->use_regex;
	C.cflags = msg->cflags;
	C.eflags = msg->eflags;
	msg->find = NULL;
	msg->files = NULL;
	msg->include = NULL;
	msg->exclude = NULL;
	C.ready = 1;
	if (C.use_regex) {
		if (C.find_len > 0 && jstr_re_comp(&C.regex, C.find, C.cflags) != JSTR_RE_RET_NOERROR)
			C.ready = 0;
	} else {
		jstr_memmem_comp(&C.twoway, C.find, C.find_len);
	}
	if (C.include_len > 0 && jstr_re_comp(&C.inc_re, C.include, C.cflags) == JSTR_RE_RET_NOERROR)
		C.have_inc = 1;
	if (C.exclude_len > 0 && jstr_re_comp(&C.exc_re, C.exclude, C.cflags) == JSTR_RE_RET_NOERROR)
		C.have_exc = 1;
}

/**
 * @anchor spec_cfg_accept
 * @brief Test a file against D-local find/filter configuration.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param fname file name.
 * @param fname_len FNAME byte length.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static int
cfg_accept(const char *R fname, size_t fname_len)
{
	if (C.files_len > 0 && jstr_strstr_len(fname, fname_len, C.files, C.files_len) == NULL)
		return 0;
	const char *base = jstr_memrchr(fname, '/', fname_len);
	base = (base != NULL && *(base + 1)) ? base + 1 : fname;
	const size_t base_len = (size_t)(fname + fname_len - base);
	if (C.have_inc && jstr_re_match_len(&C.inc_re, base, base_len, 0) != JSTR_RE_RET_NOERROR)
		return 0;
	if (C.have_exc && jstr_re_match_len(&C.exc_re, base, base_len, 0) == JSTR_RE_RET_NOERROR)
		return 0;
	return 1;
}

/**
 * @anchor spec_batch_discard
 * @brief Free a partially built D match batch.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static void
batch_discard(void)
{
	for (size_t i = 0; i < batch_n; ++i)
		free(batch[i].owner);
	batch_n = 0;
	batch_files = 0;
}

/**
 * @anchor spec_grep_msg_alloc
 * @brief Allocate or recycle a grep message object.
 * @details Prefers the Stage C return queue; falls back to calloc. The returned
 *          object is zeroed before use.
 * @return Zeroed grep message object; terminates on allocation failure.
 * @post Caller owns the object and must publish or return it.
 * @par Side Effects:
 *   Consumes a recycled object if available; may allocate memory.
 * @par Threading and Reentrancy:
 *   Called only by Stage D.
 */
static far_grep_msg_ty *
grep_msg_alloc(void)
{
	far_grep_msg_ty *msg = pipeline_grep_msg_return_try_recv(d_worker);
	if (msg == NULL)
		msg = (far_grep_msg_ty *)calloc(1, sizeof *msg);
	if (jstr_unlikely(msg == NULL))
		jstr_errdie("%s", "Out of memory.\n");
	memset(msg, 0, sizeof *msg);
	return msg;
}

/**
 * @anchor spec_grep_msg_release
 * @brief Return a grep message object for reuse.
 * @details Best-effort non-blocking return to Stage D; falls back to free.
 * @pre MSG is no longer referenced by the caller.
 * @param msg Message object to release.
 * @post Caller must not access MSG.
 * @par Side Effects:
 *   Publishes a pointer or frees it.
 * @par Threading and Reentrancy:
 *   Called by Stage C or D.
 */
static void
grep_msg_release(far_grep_msg_ty *msg)
{
	if (msg == NULL)
		return;
	if (pipeline_grep_msg_return_try_send(d_worker, msg) != 0)
		free(msg);
}

/**
 * @anchor spec_batch_flush
 * @brief Publish the current D match batch to C.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static void
batch_flush(void)
{
	if (batch_n == 0)
		return;
	far_grep_msg_ty *const msg = grep_msg_alloc();
	msg->kind = FAR_GREP_MATCH;
	msg->gen = batch_gen;
	memcpy(msg->lines, batch, batch_n * sizeof *msg->lines);
	msg->count = batch_n;
	msg->files_matched = batch_files;
	if (pipeline_grep_msg_send(d_worker, msg) != 0) {
		for (size_t i = 0; i < batch_n; ++i)
			free(batch[i].owner);
		grep_msg_release(msg);
	}
	batch_n = 0;
	batch_files = 0;
}

/**
 * @anchor spec_send_one_match
 * @brief Append one owned match record to the D batch.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param fname file name.
 * @param fname_len FNAME byte length.
 * @param line destination line buffer or worker queue index.
 * @param data data bytes.
 * @param len valid byte count.
 * @param moff parameter defined by the owning module contract.
 * @param mlen parameter defined by the owning module contract.
 * @param first first-match-in-file flag.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static void
send_one_match(const char *R fname, size_t fname_len, size_t line,
               const char *R data, size_t len, size_t moff, size_t mlen, int first)
{
	if (moff > len)
		moff = 0;
	if (mlen > len - moff)
		mlen = len - moff;
	char *const block = (char *)malloc(fname_len + 1 + len + 1);
	if (jstr_unlikely(!block))
		return;
	memcpy(block, fname, fname_len);
	block[fname_len] = '\0';
	memcpy(block + fname_len + 1, data, len);
	block[fname_len + 1 + len] = '\0';
	grep_line_ty *const gl = &batch[batch_n++];
	gl->fname = block;
	gl->fname_len = fname_len;
	gl->line_num = line;
	gl->content = block + fname_len + 1;
	gl->content_len = len;
	gl->match_off = moff;
	gl->match_len = mlen;
	gl->owner = block;
	batch_gen = C.gen;
	if (first)
		++batch_files;
	if (batch_n == GREP_BATCH_MAX)
		batch_flush();
}

/**
 * @anchor spec_scan_content
 * @brief Scan one cached file and emit matching lines.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param fname file name.
 * @param fname_len FNAME byte length.
 * @param buf growable byte buffer.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static void
scan_content(const char *R fname, size_t fname_len, const jstr_ty *R buf)
{
	if (!C.ready || !cfg_accept(fname, fname_len))
		return;
	const char *d = buf->data;
	const size_t n = buf->size;
	const char *p = d;
	int first = 1;
	for (size_t line = 1;; ++line) {
		const char *nl = (const char *)memchr(p, '\n', (size_t)(d + n - p));
		const size_t line_len = (nl != NULL) ? (size_t)(nl - p) : (size_t)(d + n - p);
		const char *const line_data = line_len ? p : "";
		int matched = 0;
		size_t moff = 0;
		size_t mlen = 0;
		if (C.find_len == 0) {
			matched = 1;
		} else if (C.use_regex) {
			regmatch_t rm = { 0 };
			matched = (jstr_re_search_len(&C.regex, line_data, line_len, &rm, C.eflags) == JSTR_RE_RET_NOERROR);
			if (matched) {
				moff = (size_t)rm.rm_so;
				mlen = (size_t)(rm.rm_eo - rm.rm_so);
			}
		} else {
			const char *hit = (const char *)jstr_memmem_exec(&C.twoway, p, line_len, C.find, C.find_len);
			if (hit != NULL) {
				matched = 1;
				moff = (size_t)(hit - p);
				mlen = C.find_len;
			}
		}
		if (matched) {
			if (sent_matches >= C.limit)
				return;
			send_one_match(fname, fname_len, line, line_data, line_len, moff, mlen, first);
			++sent_matches;
			first = 0;
			if (C.limit != (size_t)-1)
				batch_flush();
		}
		if (nl == NULL)
			break;
		p = nl + 1;
	}
}

/**
 * @anchor spec_send_kind
 * @brief Publish one control message from D to C.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param kind message kind discriminator.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static void
send_kind(far_grep_msg_kind_ty kind)
{
	batch_flush();
	far_grep_msg_ty *const msg = grep_msg_alloc();
	msg->kind = kind;
	msg->gen = C.gen;
	if (pipeline_grep_msg_send(d_worker, msg) != 0)
		grep_msg_release(msg);
}

/**
 * @anchor spec_rescan_all
 * @brief Rescan all cached files under the current D configuration.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param full parameter defined by the owning module contract.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static void
rescan_all(int full)
{
	sent_matches = 0;
	batch_discard();
	for (size_t i = 0; i < cache_size; ++i) {
		cached_file_ty *const file = &cache[i];
		if (file->state == CACHE_CACHED) {
			scan_content(file->fname, file->fname_len, &file->content);
			continue;
		}
		struct stat st;
		if (xstat(file->fname, &st) != JSTR_RET_SUCC)
			continue;
		file->size = (size_t)st.st_size;
		file->mode = st.st_mode;
		jstr_ty tmp = (jstr_ty)JSTR_INIT;
		if (jstr_chk(jstr_reserve_j(&tmp, file->size)) ||
		    jstr_chk(jstr_io_readfile_len_j(&tmp, file->fname, 0, file->size))) {
			jstr_free_j(&tmp);
			continue;
		}
		scan_content(file->fname, file->fname_len, &tmp);
		jstr_free_j(&tmp);
	}
	(void)full;
	send_kind(FAR_GREP_DONE);
}

/**
 * @anchor spec_cache_add
 * @brief Add one file to the D content cache.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param fname file name.
 * @param fname_len FNAME byte length.
 * @param size valid byte count.
 * @param mode new editor mode.
 * @param content parameter defined by the owning module contract.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static cached_file_ty *
cache_add(const char *R fname, size_t fname_len, size_t size, unsigned int mode, jstr_ty *R content)
{
	if (cache_size >= cache_cap) {
		cache_cap = cache_cap == 0 ? 32 : cache_cap * 2;
		cached_file_ty *const tmp = (cached_file_ty *)realloc(cache, cache_cap * sizeof *tmp);
		if (jstr_unlikely(!tmp))
			jstr_errdie("%s", "Out of memory.\n");
		cache = tmp;
	}
	cached_file_ty *const file = &cache[cache_size++];
	memset(file, 0, sizeof *file);
	file->fname = (char *)malloc(fname_len + 1);
	if (jstr_unlikely(!file->fname))
		jstr_errdie("%s", "Out of memory.\n");
	memcpy(file->fname, fname, fname_len);
	file->fname[fname_len] = '\0';
	file->fname_len = fname_len;
	file->size = size;
	file->mode = mode;
	file->content = (jstr_ty)JSTR_INIT;
	if (cache_bytes + content->size <= cache_max) {
		file->content = *content;
		*content = (jstr_ty)JSTR_INIT;
		file->state = CACHE_CACHED;
		cache_bytes += file->content.size;
	}
	return file;
}

/**
 * @anchor spec_handle_result
 * @brief Consume one raw Stage-B result in Stage D.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param res result object produced by Stage B.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static void
handle_result(far_result_ty *R res)
{
	if (res->kind == FAR_RES_EOS) {
		pending_eos = 1;
		pending_eos_total = res->total;
		ui_result_free(res);
		if (data_seen >= pending_eos_total) {
			send_kind(FAR_GREP_EOS);
			pending_eos = 0;
			data_seen = 0;
		}
		return;
	}
	++data_seen;
	if (res->pr.err) {
		send_kind(FAR_GREP_ERROR);
		ui_result_free(res);
		return;
	}
	if (res->pr.out == NULL) {
		ui_result_free(res);
		return;
	}
	cached_file_ty *const file = cache_add(res->path, res->path_len,
	                                       (size_t)res->pr.st.st_size, res->pr.st.st_mode,
	                                       res->pr.out);
	scan_content(file->fname, file->fname_len, file->state == CACHE_CACHED ? &file->content : res->pr.out);
	ui_result_free(res);
}

/**
 * @anchor spec_retire_free_all
 * @brief Free an entire retired match list.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param lines match list to modify or retire.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static void
retire_free_all(grep_lines_ty *lines)
{
	for (size_t i = 0; i < lines->size; ++i)
		free(lines->data[i].owner);
	free(lines->data);
	free(lines);
}

/**
 * @anchor spec_retire_step
 * @brief Free a bounded slice of one retired match list.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
static int
retire_step(void)
{
	if (retire_cur == NULL) {
		retire_cur = pipeline_grep_retire_try_recv(d_worker);
		retire_at = 0;
		if (retire_cur == NULL)
			return 0;
	}
	const size_t end = JSTR_MIN(retire_cur->size, retire_at + 4096);
	for (size_t i = retire_at; i < end; ++i)
		free(retire_cur->data[i].owner);
	retire_at = end;
	if (retire_at >= retire_cur->size) {
		grep_lines_ty *const done = retire_cur;
		retire_cur = NULL;
		free(done->data);
		if (pipeline_retire_node_return_try_send(d_worker, done) != 0)
			free(done);
	}
	return 1;
}

/**
 * @anchor spec_grep_worker_log_start
 * @brief Append one byte to the optional D-worker startup log.
 *
 * @details Used by integration tests to verify the configured D worker count.
 *          Failure to open or write the log is ignored.
 * @par Side Effects:
 *   Appends to the file named by `FAR_GREP_WORKER_LOG` when set.
 * @par Threading and Reentrancy:
 *   Called once by each Stage D worker at startup.
 */
static void
grep_worker_log_start(void)
{
	const char *const path = getenv("FAR_GREP_WORKER_LOG");
	if (path == NULL)
		return;
	FILE *const fp = fopen(path, "ab");
	if (fp == NULL)
		return;
	(void)fputc('x', fp);
	(void)fclose(fp);
}

/**
 * @anchor spec_grep_worker_thread
 * @brief Stage-D scan/cache loop.
 *
 * @details This function is part of the grep_worker.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param arg parameter defined by the owning module contract.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D only.
 */
far_thread_ret_ty
grep_worker_thread(void *arg)
{
	d_worker = (size_t)(uintptr_t)arg;
	grep_worker_log_start();
	cache_max = procfs_mem_available() / 2;
	const size_t workers = pipeline_worker_count();
	if (workers != 0)
		cache_max /= workers;
	unsigned int spin = 0;
	for (;;) {
		int did = 0;
		grep_cfg_ty *cfg;
		while ((cfg = pipeline_grep_cfg_try_recv(d_worker)) != NULL) {
			const int full = cfg->kind == GREP_CFG_FULL;
			const int stop = cfg->kind == GREP_CFG_STOP;
			if (stop)
				goto out;
			cfg_compile(cfg);
			free(cfg);
			rescan_all(full);
			did = 1;
		}
		if (retire_step())
			did = 1;
		far_result_ty *res;
		while ((res = pipeline_grep_work_try_recv(d_worker)) != NULL) {
			handle_result(res);
			did = 1;
		}
		if (pending_eos && data_seen >= pending_eos_total) {
			send_kind(FAR_GREP_EOS);
			pending_eos = 0;
			data_seen = 0;
			did = 1;
		}
		if (did)
			spin = 0;
		else
			spsc_backoff(&spin);
	}
out:
	{
		far_grep_msg_ty *msg;
		while ((msg = pipeline_grep_msg_return_try_recv(d_worker)) != NULL)
			free(msg);
	}
	if (retire_cur != NULL)
		retire_free_all(retire_cur);
	{
		grep_lines_ty *pending;
		while ((pending = pipeline_grep_retire_try_recv(d_worker)) != NULL)
			retire_free_all(pending);
	}
	batch_discard();
	for (size_t i = 0; i < cache_size; ++i) {
		free(cache[i].fname);
		jstr_free_j(&cache[i].content);
	}
	free(cache);
	cfg_clear();
	return FAR_THREAD_RETURN;
}
