/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "process.h"
#include "files.h"
#include "confirm.h"

#include <stdarg.h>
#include <string.h>

/* Number of leading bytes scanned for NULs when deciding a file is binary;
 * covers the usual text/binary header region without reading the whole file. */
#define BINARY_SCAN_SIZE (JSTR_IO_KIB * 4)

/* Fatal per-file error: pipeline workers capture the rendered message into PE
 * and fail the job (the emitter prints it in traversal order); every other
 * caller dies on the spot exactly like before threading existed. */
#define FATAL_OR_CAPTURE(pe, ...)                                                  \
	do {                                                                           \
		if ((pe) != NULL) {                                                        \
			(void)snprintf((pe)->buf, sizeof((pe)->buf), __VA_ARGS__);             \
			(pe)->set = 1;                                                         \
			JSTR_RETURN_ERR(JSTR_RET_ERR);                                         \
		}                                                                          \
		jstr_errdie(__VA_ARGS__);                                                  \
	} while (0)

/* Match FIND against one line [P, P+LINE_LEN): regex via G.regex or fixed
 * string via the precompiled Two-Way matcher. Read-only over the shared
 * compiled state, so it is safe to call from worker threads. */
static void
grep_match_at(const jstr_twoway_ty *R t, const char *R p, size_t line_len,
              const char *R find, size_t find_len,
              int *matched, size_t *moff, size_t *mlen)
{
	if (G.mode & MODE_USE_REGEX) {
		regmatch_t rm = { 0 };
		*matched = (jstr_re_search_len(&G.regex, p, line_len, &rm, G.eflags) == JSTR_RE_RET_NOERROR);
		if (*matched) {
			*moff = (size_t)rm.rm_so;
			*mlen = (size_t)(rm.rm_eo - rm.rm_so);
		}
	} else {
		const char *hit = (const char *)jstr_memmem_exec(t, p, line_len, find, find_len);
		if (hit != NULL) {
			*matched = 1;
			*moff = (size_t)(hit - p);
			*mlen = find_len;
		}
	}
}

/* Whole-buffer fixed-string line scan: find every line containing FIND with
 * one Two-Way pass over the buffer instead of one call per line (the
 * per-line loop's call overhead dominated scans of large caches). Line
 * boundaries are derived per hit; a hit is rejected when FIND itself spans a
 * newline, preserving the per-line grep semantics exactly. */
typedef void (*grep_line_cb)(void *R ctx, size_t line_no,
                             const char *R line, size_t line_len,
                             size_t moff, size_t mlen);

static void
grep_iter_fixed(const jstr_twoway_ty *R t, const char *R d, size_t n,
                const char *R find, size_t find_len,
                grep_line_cb cb, void *R ctx)
{
	const char *end = d + n;
	const char *p = d;
	const char *line_start = d;
	size_t line = 1;
	for (;;) {
		const char *hit;
		const char *le;
		const char *ls;
		if (p >= end)
			break;
		hit = (const char *)jstr_memmem_exec(t, p, (size_t)(end - p), find, find_len);
		if (hit == NULL)
			break;
		/* Reject matches spanning a newline: per-line scanning could never
		 * produce them. */
		if (memchr(hit, '\n', find_len) != NULL) {
			p = hit + 1;
			continue;
		}
		/* Roll the line counter up to the hit's line. */
		ls = line_start;
		for (;;) {
			const char *nl = (const char *)memchr(ls, '\n', (size_t)(hit - ls));
			if (nl == NULL)
				break;
			ls = nl + 1;
			++line;
		}
		line_start = ls;
		le = (const char *)memchr(hit, '\n', (size_t)(end - hit));
		le = (le != NULL) ? le : end;
		cb(ctx, line, line_start, (size_t)(le - line_start), (size_t)(hit - line_start), find_len);
		p = (le < end) ? le + 1 : end;
	}
}

/* Append S/N to OUT, failing cleanly on OOM (workers may not die). */
static jstr_ret_ty
out_append(jstr_ty *R out, const char *R s, size_t n)
{
	if (n == 0)
		return JSTR_RET_SUCC;
	return jstr_append_len_j(out, s, n);
}

/* Render the "FNAME:LINE:" prefix of a grep line into OUT (buffer variant of
 * print_line_prefix for the threaded pipeline). */
static jstr_ret_ty
append_line_prefix(jstr_ty *R out, const char *R fname, size_t fname_len, size_t line)
{
	char num[24];
	if (fname != NULL) {
		if (jstr_chk(out_append(out, TUI_GREP_FILENAME, S_LEN(TUI_GREP_FILENAME))))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		if (jstr_chk(out_append(out, fname, fname_len)))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		if (jstr_chk(out_append(out, TUI_GREP_UNMATCHED, S_LEN(TUI_GREP_UNMATCHED))))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		if (jstr_chk(out_append(out, ":", 1)))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	if (jstr_chk(out_append(out, TUI_GREP_LINENUMBER, S_LEN(TUI_GREP_LINENUMBER))))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	(void)snprintf(num, sizeof(num), "%zu", line);
	if (jstr_chk(out_append(out, num, strlen(num))))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (jstr_chk(out_append(out, TUI_GREP_UNMATCHED, S_LEN(TUI_GREP_UNMATCHED))))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return out_append(out, ":", 1);
}

/* Print the "FNAME:LINE:" prefix of a grep line. */
static jstr_ret_ty
print_line_prefix(const char *R fname, size_t fname_len, size_t line)
{
	if (jstr_likely(fname != NULL)) {
		(void)jstr_io_fwrite(TUI_GREP_FILENAME, 1, S_LEN(TUI_GREP_FILENAME), stdout);
		(void)jstr_io_fwrite(fname, 1, fname_len, stdout);
		(void)jstr_io_fwrite(TUI_GREP_UNMATCHED, 1, S_LEN(TUI_GREP_UNMATCHED), stdout);
		(void)jstr_io_fputc(':', stdout);
	}
	(void)jstr_io_fwrite(TUI_GREP_LINENUMBER, 1, S_LEN(TUI_GREP_LINENUMBER), stdout);
	print_size_t(line);
	(void)jstr_io_fwrite(TUI_GREP_UNMATCHED, 1, S_LEN(TUI_GREP_UNMATCHED), stdout);
	(void)jstr_io_fputc(':', stdout);
	return JSTR_RET_SUCC;
}

/* --grep mode, fixed-string sink: print matching lines to stdout. */
struct scan_ctx_ty {
	const char *fname;
	size_t fname_len;
};

static void
scan_print_cb(void *R vctx, size_t line, const char *R lp, size_t line_len,
              size_t moff, size_t mlen)
{
			struct scan_ctx_ty *const c = (struct scan_ctx_ty *)vctx;
	G.gflags |= F_GREP_MATCHED;
	if (!(G.mode & MODE_QUIET)) {
		(void)print_line_prefix(c->fname, c->fname_len, line);
		(void)jstr_io_fwrite(lp, 1, moff, stdout);
		(void)jstr_io_fwrite(TUI_GREP_MATCHED, 1, S_LEN(TUI_GREP_MATCHED), stdout);
		(void)jstr_io_fwrite(lp + moff, 1, mlen, stdout);
		(void)jstr_io_fwrite(TUI_GREP_UNMATCHED, 1, S_LEN(TUI_GREP_UNMATCHED), stdout);
		(void)jstr_io_fwrite(lp + moff + mlen, 1, line_len - moff - mlen, stdout);
		(void)jstr_io_fputc('\n', stdout);
	}
}

/* --grep mode: print the whole content of every line that matches FIND.
 * Matching is line-based like grep (a regex can never span newlines here,
 * unlike the replace path which scans the whole buffer). */
jstr_ret_ty
grep_scan_file(const jstr_twoway_ty *R t, const jstr_ty *R buf, const char *R fname, size_t fname_len,
               const char *R find, size_t find_len)
{
	struct scan_ctx_ty c;
	if (find_len == 0)
		return JSTR_RET_SUCC;
	if (!(G.mode & MODE_USE_REGEX)) {
		c.fname = fname;
		c.fname_len = fname_len;
		grep_iter_fixed(t, buf->data, buf->size, find, find_len, scan_print_cb, &c);
		return JSTR_RET_SUCC;
	}
	{
		const char *d = buf->data;
		const size_t n = buf->size;
		const char *p = d;
		for (size_t line = 1;; ++line) {
			const char *nl = memchr(p, '\n', (size_t)(d + n - p));
			const size_t line_len = (nl != NULL) ? (size_t)(nl - p) : (size_t)(d + n - p);
			int matched = 0;
			size_t moff = 0;
			size_t mlen = 0;
			grep_match_at(t, p, line_len, find, find_len, &matched, &moff, &mlen);
			if (matched) {
				G.gflags |= F_GREP_MATCHED;
				if (!(G.mode & MODE_QUIET)) {
					(void)print_line_prefix(fname, fname_len, line);
					(void)jstr_io_fwrite(p, 1, moff, stdout);
					(void)jstr_io_fwrite(TUI_GREP_MATCHED, 1, S_LEN(TUI_GREP_MATCHED), stdout);
					(void)jstr_io_fwrite(p + moff, 1, mlen, stdout);
					(void)jstr_io_fwrite(TUI_GREP_UNMATCHED, 1, S_LEN(TUI_GREP_UNMATCHED), stdout);
					(void)jstr_io_fwrite(p + moff + mlen, 1, line_len - moff - mlen, stdout);
					(void)jstr_io_fputc('\n', stdout);
				}
			}
			if (nl == NULL)
				break;
			p = nl + 1;
		}
	}
	return JSTR_RET_SUCC;
}

/* --grep TUI, fixed-string sink: append match records to G.grep_lines. */
struct collect_ctx_ty {
	grep_lines_ty *dst;
	const char *fname;
	size_t fname_len;
};

static void
collect_cb(void *R vctx, size_t line, const char *R lp, size_t line_len,
           size_t moff, size_t mlen)
{
	struct collect_ctx_ty *const c = (struct collect_ctx_ty *)vctx;
	grep_lines_ty *const dst = c->dst;
	if (dst->size >= dst->cap) {
		dst->cap = (dst->cap == 0 ? 32 : dst->cap * 2);
		grep_line_ty *const tmp = (grep_line_ty *)realloc(dst->data, dst->cap * sizeof(grep_line_ty));
		DIE_IF(!tmp, "%s", "Out of memory allocating grep results.\n");
		dst->data = tmp;
	}
	dst->data[dst->size].fname = c->fname;
	dst->data[dst->size].fname_len = c->fname_len;
	dst->data[dst->size].line_num = line;
	dst->data[dst->size].content = lp;
	dst->data[dst->size].content_len = line_len;
	dst->data[dst->size].match_off = moff;
	dst->data[dst->size].match_len = mlen;
	++dst->size;
}

/* --grep TUI core: append every matching line to DST. Does not touch any
 * global state, so worker chunks can target private lists. */
void
grep_collect_file_into(grep_lines_ty *R dst, const jstr_twoway_ty *R t, const jstr_ty *R buf,
                       const char *R fname, size_t fname_len, const char *R find,
                       size_t find_len)
{
	struct collect_ctx_ty c;
	c.dst = dst;
	c.fname = fname;
	c.fname_len = fname_len;
	if (!(G.mode & MODE_USE_REGEX)) {
		grep_iter_fixed(t, buf->data, buf->size, find, find_len, collect_cb, &c);
		return;
	}
	{
		const char *d = buf->data;
		const size_t n = buf->size;
		const char *p = d;
		for (size_t line = 1;; ++line) {
			const char *nl = memchr(p, '\n', (size_t)(d + n - p));
			const size_t line_len = (nl != NULL) ? (size_t)(nl - p) : (size_t)(d + n - p);
			int matched = 0;
			size_t moff = 0;
			size_t mlen = 0;
			grep_match_at(t, p, line_len, find, find_len, &matched, &moff, &mlen);
			if (matched) {
				if (dst->size >= dst->cap) {
					dst->cap = (dst->cap == 0 ? 32 : dst->cap * 2);
					grep_line_ty *const tmp = (grep_line_ty *)realloc(dst->data, dst->cap * sizeof(grep_line_ty));
					DIE_IF(!tmp, "%s", "Out of memory allocating grep results.\n");
					dst->data = tmp;
				}
				dst->data[dst->size].fname = fname;
				dst->data[dst->size].fname_len = fname_len;
				dst->data[dst->size].line_num = line;
				dst->data[dst->size].content = p;
				dst->data[dst->size].content_len = line_len;
				dst->data[dst->size].match_off = moff;
				dst->data[dst->size].match_len = mlen;
				++dst->size;
			}
			if (nl == NULL)
				break;
			p = nl + 1;
		}
	}
}

/* --grep TUI: collect every matching line into G.grep_lines. */
void
grep_collect_file(const jstr_twoway_ty *R t, const jstr_ty *R buf, const char *R fname,
                  size_t fname_len, const char *R find,
                  size_t find_len)
{
	const size_t before = G.grep_lines.size;
	grep_collect_file_into(&G.grep_lines, t, buf, fname, fname_len, find, find_len);
	if (G.grep_lines.size > before)
		G.gflags |= F_GREP_MATCHED;
}

/* Report modified file path to stderr (unless quiet) and stdout (if -l is enabled). */
jstr_ret_ty
report_changed_file(const char *R fname, size_t fname_len)
{
	if (!(G.mode & MODE_QUIET)) {
		if (jstr_unlikely(jstr_io_fwrite(fname, 1, fname_len, stderr) != fname_len))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		if (jstr_unlikely(jstr_io_fputc('\n', stderr) == EOF))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	if (G.mode & MODE_PRINT_CHANGES) {
		if (jstr_unlikely(jstr_io_fwrite(fname, 1, fname_len, stdout) != fname_len))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		if (jstr_chk(jstr_io_putchar('\n')))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	return JSTR_RET_SUCC;
}

/* Write buffer to file with backup suffix (-iSUFFIX). */
static jstr_ret_ty
write_inplace_backup(const jstr_ty *R buf, const char *R fname, size_t fname_len, const struct stat *st, proc_err_ty *R pe)
{
	char bak[JSTR_IO_PATH_MAX];
	if (jstr_unlikely(fname_len + G.bak_suffix_len >= sizeof(bak)))
		FATAL_OR_CAPTURE(pe, "Suffix length is too large to create a backup file (%zu >= %zu).\n", fname_len + G.bak_suffix_len, sizeof(bak));
	char *p = jstr_mempcpy(bak, fname, fname_len);
	jstr_strcpy_len(p, G.bak_suffix, G.bak_suffix_len);
	if (jstr_unlikely(file_exists(bak)))
		FATAL_OR_CAPTURE(pe, "Can't make a backup file because suffixed filename (%s) already exists.\n", bak);
	if (jstr_unlikely(rename(fname, bak)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (jstr_chk(jstr_io_writefile_len_j(buf, fname, O_CREAT | O_TRUNC | O_WRONLY, st->st_mode & (S_IRWXO | S_IRWXG | S_IRWXU))))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_SUCC;
}

/* Write buffer atomically using a temporary file (plain -i). */
static jstr_ret_ty
write_inplace_temp(const jstr_ty *R buf, const char *R fname, size_t fname_len, proc_err_ty *R pe)
{
	int fd_tmp = -1;
	char *bakp = NULL;
	char bak[JSTR_IO_PATH_MAX];
	bakp = bak;
	if (jstr_unlikely(fname_len + S_LEN(".XXXXXX") >= sizeof(bak)))
		FATAL_OR_CAPTURE(pe, "Filename (%s) is too large to create a backup file (%zu >= %zu).\n", fname, fname_len + S_LEN(".XXXXXX"), sizeof(bak));
	{
		char *p = jstr_mempcpy(bak, fname, fname_len);
		p = jstr_stpcpy_len(p, S_LITERAL(".XXXXXX"));
	}
	fd_tmp = mkstemp(bak);
	if (jstr_unlikely(fd_tmp == -1)) {
		bakp = NULL;
		if (pe != NULL) {
			(void)snprintf(pe->buf, sizeof(pe->buf), "Can't make a file (%s) to temporarily write replacements to.\n", bak);
			pe->set = 1;
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		}
		jstr_errdie("Can't make a file (%s) to temporarily write replacements to.\n", bak);
	}
	if (jstr_chk(jstr_io_writefilefd_len_j(buf, fd_tmp))) {
		if (pe != NULL) {
			(void)snprintf(pe->buf, sizeof(pe->buf), "Can't write replacements to temp file (%s).\n", bak);
			pe->set = 1;
			goto err;
		}
		jstr_errdie("Can't write replacements to temp file (%s).\n", bak);
	}
	if (jstr_unlikely(close(fd_tmp) == -1)) {
		fd_tmp = -1;
		if (pe != NULL) {
			(void)snprintf(pe->buf, sizeof(pe->buf), "Can't close temp file (%s).\n", bak);
			pe->set = 1;
			goto err;
		}
		jstr_errdie("Can't close temp file (%s).\n", bak);
	}
	fd_tmp = -1;
	if (jstr_unlikely(rename(bak, fname))) {
		if (pe != NULL) {
			(void)snprintf(pe->buf, sizeof(pe->buf), "Can't rename temp file (%s) to original file (%s).\n", bak, fname);
			pe->set = 1;
			goto err;
		}
		jstr_errdie("Can't rename temp file (%s) to original file (%s).\n", bak, fname);
	}
	return JSTR_RET_SUCC;
err:
	if (fd_tmp != -1)
		if (close(fd_tmp) < 0) {}
	if (bakp != NULL)
		if (unlink(bakp) < 0) {}
	return JSTR_RET_ERR;
}

/* The replacement engine shared by process_buffer and the threaded pipeline:
 * run the regex or fixed-string replacement over BUF and keep the buffer
 * newline-terminated. *CHANGED receives the number of replacements. */
static jstr_ret_ty
replace_engine(const jstr_twoway_ty *R t,
               jstr_ty *R buf,
               const char *R find,
               const size_t find_len,
               const char *R rplc,
               const size_t rplc_len,
               size_t *changed_out,
               proc_err_ty *R pe)
{
	/* Holds the length of the replaced output. As a size_t when the fixed
	 * and regex paths both store a length; the regex variant returns a
	 * signed offset type that may hold a negative error code. */
	union u {
		size_t zu;
		jstr_re_off_ty d;
	} changed;
	if (G.mode & MODE_USE_REGEX) {
		/* Temporarily remove trailing newline. */
		if (buf->size && buf->data[buf->size - 1] == '\n') {
			buf->data[buf->size - 1] = '\0';
			--buf->size;
		}
		changed.d = jstr_re_rplcn_backref_len_exec_j(&G.regex, buf, rplc, rplc_len, G.eflags, JSTR_NMATCH_MAX, G.n);
		if (jstr_re_chk(changed.d)) {
			if (pe != NULL) {
				(void)snprintf(pe->buf, sizeof(pe->buf), "%s", "Regex replacement failed.\n");
				pe->set = 1;
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			jstr_re_errdie(changed.d, &G.regex, "%s", "Regex replacement failed.\n");
		}
		changed.zu = (size_t)changed.d;
	} else {
		/* Fixed-string path uses the precompiled Two-Way matcher. */
		changed.zu = jstr_rplcn_len_exec_j(t, buf, find, find_len, rplc, rplc_len, G.n);
		if (jstr_unlikely(changed.zu == (size_t)-1))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	*changed_out = changed.zu;
	return JSTR_RET_SUCC;
}

jstr_ret_ty
process_buffer(const jstr_twoway_ty *R t,
                  jstr_ty *R buf,
                  const char *R fname,
                  size_t fname_len,
                  const struct stat *st,
                  const char *R find,
                  const size_t find_len,
                  const char *R rplc,
                  const size_t rplc_len,
                  proc_err_ty *R pe)
{
	size_t changed;
	if (jstr_chk(replace_engine(t, buf, find, find_len, rplc, rplc_len, &changed, pe)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	/* Append newline if has space */
	/* Keep the final buffer newline-terminated so file output ends cleanly. */
	if (buf->size && buf->data[buf->size - 1] != '\n') {
		if (jstr_unlikely(jstr_pushback_j(buf, '\n')))
			FATAL_OR_CAPTURE(pe, "%s", "Out of memory.\n");
	}
	if (G.mode & MODE_PRINT_STDOUT) {
		/* Default mode: write the (replaced) buffer to stdout. */
		if (jstr_unlikely(jstr_io_fwrite(buf->data, 1, buf->size, stdout) != buf->size))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	} else {
		/* In-place mode (-i): nothing to do if nothing changed. */
		if (changed == 0)
			return JSTR_RET_SUCC;
		if (G.mode & MODE_PRINT_FILE_BACKUP) {
			if (jstr_chk(write_inplace_backup(buf, fname, fname_len, st, pe)))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		} else {
			if (jstr_chk(write_inplace_temp(buf, fname, fname_len, pe)))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		}
		if (jstr_chk(report_changed_file(fname, fname_len)))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	return JSTR_RET_SUCC;
}

jstr_ret_ty
process_file(const jstr_twoway_ty *R t,
                jstr_ty *R buf,
                const char *R fname,
                size_t fname_len,
                const struct stat *st,
                const char *R find,
                const size_t find_len,
                const char *R rplc,
                const size_t rplc_len)
{
	const size_t file_size = (size_t)st->st_size;
	/* A fixed-string find longer than the whole file cannot match. In the
	 * interactive editor or grep TUI, the find can still be edited to
	 * something shorter, so keep such files cached there. */
	if (!(G.mode & MODE_USE_REGEX) && file_size < find_len &&
	    !((G.mode & (MODE_CONFIRM | MODE_GREP)) && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)))
		return JSTR_RET_SUCC;
	/* Preallocate the length of the replace string. */
	/* Worst-case output size = input + (longer replace) + trailing newline. */
	if (rplc_len > find_len && !(G.mode & MODE_USE_REGEX))
		if (jstr_chk(jstr_reserve_j(buf, file_size + rplc_len - find_len + S_LEN("\n") + 1)))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (jstr_chk(jstr_io_readfile_len_j(buf, fname, 0, file_size)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	/* Skip files with NUL bytes in the first BINARY_SCAN_SIZE bytes. */
	if (jstr_io_isbinary_atleast(buf->data, file_size, BINARY_SCAN_SIZE))
		return JSTR_RET_SUCC;
	/* --grep mode: cache files for the TUI, or print matching lines directly. */
	if (G.mode & MODE_GREP) {
		if (G.gflags & F_GREP_COLLECT) {
			file_pushback(&G.files, fname, fname_len, st, buf);
			return JSTR_RET_SUCC;
		}
		return grep_scan_file(t, buf, fname, fname_len, find, find_len);
	}
	/* During the -c dry-run pass, only scan and preview; the real edit
	 * happens on the second pass after the user confirms. The file's content
	 * is recorded so pass 2 edits it from memory without re-reading disk. */
	if ((G.gflags & F_CONFIRM_PASS) && (G.mode & MODE_CONFIRM)) {
		/* Interactive mode: pass 1 only caches files. The confirm TUI scans
		 * each cached buffer live (bounded to the preview budget) on every
		 * redraw, so a pre-scan here would both dump the whole diff to stdout
		 * before the editor opens and, with -g on a large tree, stall the
		 * startup on an unbounded match collection. */
		if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
			file_pushback(&G.files, fname, fname_len, st, buf);
			return JSTR_RET_SUCC;
		}
		{
			size_t matches = 0;
			jstr_ret_ty ret = confirm_scan_file(t, buf, fname, fname_len, find, find_len, rplc, rplc_len, &matches);
			/* Only files with matches need editing on pass 2; steal their buffer. */
			if (matches > 0)
				file_pushback(&G.files, fname, fname_len, st, buf);
			return ret;
		}
	}
	return process_buffer(t, buf, fname, fname_len, st, find, find_len, rplc, rplc_len, NULL);
}

int
pipeline_read_file(jstr_ty *R buf, const char *R fname, size_t fname_len, const struct stat *st)
{
	const size_t file_size = (size_t)st->st_size;
	(void)fname_len;
	if (jstr_chk(jstr_io_readfile_len_j(buf, fname, 0, file_size)))
		return PIPELINE_READ_ERR;
	/* Skip files with NUL bytes in the first BINARY_SCAN_SIZE bytes. */
	if (jstr_io_isbinary_atleast(buf->data, file_size, BINARY_SCAN_SIZE))
		return PIPELINE_READ_BINARY;
	return PIPELINE_READ_OK;
}

/* --grep pipeline worker, fixed-string sink: append formatted lines to OUT. */
struct scan_buf_ctx {
	jstr_ty *out;
	const char *fname;
	size_t fname_len;
	int any;
	int err;
};

static void
scan_to_buf_cb(void *R vctx, size_t line, const char *R lp, size_t line_len,
               size_t moff, size_t mlen)
{
	struct scan_buf_ctx *const c = (struct scan_buf_ctx *)vctx;
	char num[24];
	c->any = 1;
	if (c->err)
		return;
	if (jstr_chk(append_line_prefix(c->out, c->fname, c->fname_len, line)))
		c->err = 1;
	else if (jstr_chk(out_append(c->out, lp, moff)))
		c->err = 1;
	else if (jstr_chk(out_append(c->out, TUI_GREP_MATCHED, S_LEN(TUI_GREP_MATCHED))))
		c->err = 1;
	else if (jstr_chk(out_append(c->out, lp + moff, mlen)))
		c->err = 1;
	else if (jstr_chk(out_append(c->out, TUI_GREP_UNMATCHED, S_LEN(TUI_GREP_UNMATCHED))))
		c->err = 1;
	else if (jstr_chk(out_append(c->out, lp + moff + mlen, line_len - moff - mlen)))
		c->err = 1;
	else if (jstr_chk(out_append(c->out, "\n", 1)))
		c->err = 1;
	(void)num;
}

/* --grep pipeline worker: append every matching line (fully formatted, colors
 * included) to OUT unless quiet. Never touches G or stdio: the matched
 * verdict travels back through ANY_MATCHED and the emitter owns the rest. */
static void
grep_scan_to_buf(const jstr_twoway_ty *R t, const jstr_ty *R buf, jstr_ty *R out,
                 const char *R fname, size_t fname_len,
                 const char *R find, size_t find_len, int *any_matched,
                 int *err_out)
{
	struct scan_buf_ctx c;
	const int quiet = (G.mode & MODE_QUIET) != 0;
	*any_matched = 0;
	*err_out = 0;
	if (find_len == 0)
		return;
	if (!(G.mode & MODE_USE_REGEX)) {
		c.out = out;
		c.fname = fname;
		c.fname_len = fname_len;
		c.any = 0;
		c.err = 0;
		grep_iter_fixed(t, buf->data, buf->size, find, find_len, scan_to_buf_cb, &c);
		*any_matched = c.any;
		*err_out = c.err;
		return;
	}
	{
		const char *d = buf->data;
		const size_t n = buf->size;
		const char *p = d;
		for (size_t line = 1;; ++line) {
			const char *nl = memchr(p, '\n', (size_t)(d + n - p));
			const size_t line_len = (nl != NULL) ? (size_t)(nl - p) : (size_t)(d + n - p);
			int matched = 0;
			size_t moff = 0;
			size_t mlen = 0;
			grep_match_at(t, p, line_len, find, find_len, &matched, &moff, &mlen);
			if (matched) {
				*any_matched = 1;
				if (!quiet) {
					if (jstr_chk(append_line_prefix(out, fname, fname_len, line))) {
						*err_out = 1;
						return;
					}
					if (jstr_chk(out_append(out, p, moff)) ||
					    jstr_chk(out_append(out, TUI_GREP_MATCHED, S_LEN(TUI_GREP_MATCHED))) ||
					    jstr_chk(out_append(out, p + moff, mlen)) ||
					    jstr_chk(out_append(out, TUI_GREP_UNMATCHED, S_LEN(TUI_GREP_UNMATCHED))) ||
					    jstr_chk(out_append(out, p + moff + mlen, line_len - moff - mlen)) ||
					    jstr_chk(out_append(out, "\n", 1))) {
						*err_out = 1;
						return;
					}
				}
			}
			if (nl == NULL)
				break;
			p = nl + 1;
		}
	}
}

jstr_ret_ty
pipeline_process_file(const jstr_twoway_ty *R t,
                      jstr_ty *R buf,
                      const char *R fname,
                      size_t fname_len,
                      const struct stat *st,
                      const char *R find,
                      size_t find_len,
                      const char *R rplc,
                      size_t rplc_len,
                      proc_err_ty *R pe,
                      jstr_ty *R out,
                      int *flags_out)
{
	const size_t file_size = (size_t)st->st_size;
	*flags_out = 0;
	/* A fixed-string find longer than the whole file cannot match. */
	if (!(G.mode & MODE_USE_REGEX) && file_size < find_len)
		return JSTR_RET_SUCC;
	/* Worst-case output size = input + (longer replace) + trailing newline. */
	if (rplc_len > find_len && !(G.mode & MODE_USE_REGEX))
		if (jstr_chk(jstr_reserve_j(buf, file_size + rplc_len - find_len + S_LEN("\n") + 1)))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (jstr_chk(jstr_io_readfile_len_j(buf, fname, 0, file_size)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	/* Skip files with NUL bytes in the first BINARY_SCAN_SIZE bytes. */
	if (jstr_io_isbinary_atleast(buf->data, file_size, BINARY_SCAN_SIZE))
		return JSTR_RET_SUCC;
	/* --grep mode: format the matching lines for the emitter to print. */
	if (G.mode & MODE_GREP) {
		int any_matched = 0;
		int err = 0;
		grep_scan_to_buf(t, buf, out, fname, fname_len, find, find_len, &any_matched, &err);
		if (err)
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		if (any_matched)
			*flags_out |= PIPELINE_F_MATCHED;
		return JSTR_RET_SUCC;
	}
	{
		size_t changed = 0;
		if (jstr_chk(replace_engine(t, buf, find, find_len, rplc, rplc_len, &changed, pe)))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		/* Keep the final buffer newline-terminated so file output ends cleanly. */
		if (buf->size && buf->data[buf->size - 1] != '\n') {
			if (jstr_unlikely(jstr_pushback_j(buf, '\n')))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		}
		if (G.mode & MODE_PRINT_STDOUT) {
			/* Hand the replaced content to the emitter: swap the shells so
			 * the worker's buffer keeps its allocation for the next file. */
			jstr_ty tmp = *out;
			*out = *buf;
			*buf = tmp;
			return JSTR_RET_SUCC;
		}
		/* In-place mode (-i): nothing to do if nothing changed. */
		if (changed == 0)
			return JSTR_RET_SUCC;
		if (G.mode & MODE_PRINT_FILE_BACKUP) {
			if (jstr_chk(write_inplace_backup(buf, fname, fname_len, st, pe)))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		} else {
			if (jstr_chk(write_inplace_temp(buf, fname, fname_len, pe)))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		}
		*flags_out |= PIPELINE_F_CHANGED;
		return JSTR_RET_SUCC;
	}
}
