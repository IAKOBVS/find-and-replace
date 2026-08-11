/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "confirm.h"
#include "files.h"

/* Append one match range to the dynamically grown matches array. */
static void
match_pushback(matches_ty *R matches,
                  size_t start,
                  size_t end,
                  const regmatch_t *rm)
{
	if (matches->size >= matches->cap) {
		matches->cap = (matches->cap == 0 ? MATCHES_CAP_MIN : matches->cap * 2);
		match_ty *const new_matches = (match_ty *)realloc(matches->data, matches->cap * sizeof(match_ty));
		DIE_IF(!new_matches, "%s", "Out of memory allocating matches.\n");
		matches->data = new_matches;
	}
	(matches->data)[matches->size].start = start;
	(matches->data)[matches->size].end = end;
	if (rm) {
		memcpy((matches->data)[matches->size].rm, rm, 10 * sizeof(regmatch_t));
	} else {
		memset((matches->data)[matches->size].rm, 0, 10 * sizeof(regmatch_t));
	}
	++matches->size;
}

/* Append one file to the -c confirm cache. The name is strdup'd because
 * ftw->dirpath is a transient buffer reused across callbacks; the content
 * buffer is stolen from the shared buf so pass 2 needs no disk I/O. */
void
file_pushback(files_ty *files,
                 const char *R fname,
                 size_t fname_len,
                 const struct stat *st,
                 jstr_ty *R buf)
{
	if (files->size >= files->cap) {
		files->cap = (files->cap == 0 ? FILES_CAP_MIN : files->cap * 2);
		file_ty *const tmp = (file_ty *)realloc(files->data, files->cap * sizeof(file_ty));
		DIE_IF(!tmp, "%s", "Out of memory allocating cached files.\n");
		files->data = tmp;
	}
	file_ty *file = &files->data[files->size];
	file->fname = (char *)malloc(fname_len + 1);
	DIE_IF(!file->fname, "%s", "Out of memory copying cached filename.\n");
	jstr_strcpy_len(file->fname, fname, fname_len);
	file->fname_len = fname_len;
	file->content_size = (size_t)st->st_size;
	file->st_mode = st->st_mode;
	/* Take ownership of the already-read content and reset the shared buffer. */
	if (jstr_likely(files->total_content_size < FILE_CACHE_MAX)) {
		file->content = *buf;
		*buf = (jstr_ty)JSTR_INIT;
		files->total_content_size += file->content_size;
	} else {
		file->content = (jstr_ty)JSTR_INIT;
	}
	++files->size;
}

/* Return the offset of the first byte of the line containing IDX. */
static size_t
line_get_start(const char *R data, size_t size, size_t idx)
{
	const char *nl;
	if (idx > size)
		idx = size;
	nl = (const char *)jstr_memrchr(data, '\n', idx);
	return nl ? (size_t)JSTR_PTR_DIFF(nl, data) + 1 : 0;
}

/* Return one past the last byte of the line containing IDX (the index of the
 * terminating '\n', or SIZE if the line is not newline-terminated). */
static size_t
line_get_end(const char *R data, size_t size, size_t idx)
{
	const char *nl = (const char *)memchr(data + idx, '\n', size - idx);
	return nl ? (size_t)JSTR_PTR_DIFF(nl, data) : size;
}

/* Incremental 1-based line-number counter for one buffer. Requests must be
 * monotonically non-decreasing within a file, so the counter only scans the
 * region it has not visited yet: a whole pass costs O(size) newline checks
 * instead of O(requests x offset). Reset per file (the buffer changes). */
typedef struct line_counter_ty {
	const char *data;
	size_t pos;  /* Offset up to which LINE is already known. */
	size_t line; /* 1-based line number of the byte at POS. */
} line_counter_ty;

static void
line_counter_init(line_counter_ty *st, const char *R data)
{
	st->data = data;
	st->pos = 0;
	st->line = 1;
}

static size_t
line_counter_get(line_counter_ty *st, size_t idx)
{
	if (jstr_likely(idx >= st->pos)) {
		st->line += jstr_countchr_len(st->data + st->pos, '\n', idx - st->pos);
	} else {
		/* Non-monotonic request (never hit by the block loop): restart. */
		st->line = jstr_countchr_len(st->data, '\n', idx) + 1;
	}
	st->pos = idx;
	return st->line;
}

/* Return one past the last byte of the line that ends the match spanning
 * [START, END). When the match consumed the line's terminating newline, that
 * newline is the last byte of the block rather than a surviving terminator, so
 * END-1 is returned. */
static size_t
match_line_end(const char *R data, size_t size, size_t start, size_t end)
{
	if (end > start && data[end - 1] == '\n')
		return end - 1;
	return line_get_end(data, size, end);
}

/* Write VAL in decimal to stdout without using printf. */
static void
print_size_t(size_t val)
{
	char buf[3 * sizeof(val) + 2];
	size_t i = sizeof(buf);
	if (val == 0)
		buf[--i] = '0';
	while (val > 0) {
		buf[--i] = (char)('0' + val % 10);
		val /= 10;
	}
	jstr_io_fwrite(buf + i, 1, sizeof(buf) - i, stdout);
}

/* Print the "FNAME:LINE:PREFIX" prefix of one -c preview line. */
static void
print_line_prefix(const char *R fname, size_t fname_len, size_t line, char prefix)
{
	jstr_io_fwrite(fname, 1, fname_len, stdout);
	jstr_io_putchar(':');
	print_size_t(line);
	jstr_io_putchar(':');
	jstr_io_putchar(prefix);
}

/* Print one side of a -c preview change: each line of DATA is printed on its
 * own line as "FNAME:LINE:PREFIX<content>", colored with COLOR. DATA covers
 * the block from the start of the first changed line up to (but not
 * including) the '\n' that terminates the last changed line; START_LINE is
 * the line number of the first emitted line (the original file's number for
 * the '-' side, the new file's number for the '+' side). TRAILING_NL is set
 * when that terminating '\n' exists, so a DATA that itself ends in '\n' (or
 * is empty) still renders the empty line that follows it, matching how diff
 * counts lines. */
static void
print_diff_lines(const char *R data, size_t len, char prefix, const char *color, unsigned int color_len,
                    const char *R fname, size_t fname_len, size_t start_line, int trailing_nl)
{
	const char *p = data;
	const char *const end = data + len;
	size_t line = start_line;
	const char *nl;
	jstr_io_fwrite(color, 1, color_len, stdout);
	while ((nl = (const char *)memchr(p, '\n', (size_t)(end - p))) != NULL) {
		print_line_prefix(fname, fname_len, line++, prefix);
		jstr_io_fwrite(p, 1, (size_t)(nl - p), stdout);
		jstr_io_putchar('\n');
		p = nl + 1;
	}
	if (p < end) {
		/* The final line is not newline-terminated: print it as-is. */
		print_line_prefix(fname, fname_len, line, prefix);
		jstr_io_fwrite(p, 1, (size_t)(end - p), stdout);
		jstr_io_putchar('\n');
	} else if (trailing_nl) {
		/* DATA ended in '\n' (or is empty): the empty line that follows the
		 * block survives only when the block's terminating '\n' does. */
		print_line_prefix(fname, fname_len, line, prefix);
		jstr_io_putchar('\n');
	}
	jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
}

jstr_ret_ty
confirm_scan_file(const jstr_twoway_ty *R t,
                     const jstr_ty *R buf,
                     const char *R fname,
                     size_t fname_len,
                     const char *R find,
                     size_t find_len,
                     const char *R rplc,
                     size_t rplc_len,
                     size_t *R out_matches)
{
	int backref = 0;
	const unsigned char *rplc_backref1 = NULL;
	const unsigned char *rplc_backref1_e = NULL;
	if (G.mode & MODE_USE_REGEX) {
		rplc_backref1 = (const unsigned char *)jstr_internal_re_rplcbackreffirst(rplc, rplc_len);
		if (rplc_backref1 != NULL) {
			backref = 1;
			rplc_backref1_e = (const unsigned char *)jstr_internal_re_rplcbackreflast(rplc_backref1, rplc_len - JSTR_DIFF(rplc_backref1, rplc));
			if (rplc_backref1_e == NULL)
				rplc_backref1_e = rplc_backref1 + 2;
		}
	}
	/* Collect every match range so they can be grouped by line for display. */
	G.matches.size = 0;
	if (G.mode & MODE_USE_REGEX) {
		if (find_len > 0) {
			/*
			 * Scan for regex matches on the file buffer.
			 * Mirror the state machine in jstr_internal_re_rplcn_backref_len_from_exec
			 * to precisely align the on-the-fly confirm preview with actual replacements.
			 * Like process_buffer, the final trailing newline is excluded from the
			 * scanned region so regex semantics match the real replacement exactly.
			 */
			const size_t scan_size = (buf->size && buf->data[buf->size - 1] == '\n') ? buf->size - 1 : buf->size;
			size_t off = 0;
			int prev_zero = 1; /* Tracks if the previous match was zero-length. */
			size_t n = G.n;
			if (scan_size == 0)
				n = 1;
			while (n) {
				/*
				 * Stop if we are starting search at the end of the string, unless the
				 * previous match was zero-length (which lets us match anchors at EOF).
				 */
				int matched_at_end = (off == scan_size);
				if (matched_at_end) {
					if (!prev_zero)
						break;
				} else if (off > scan_size) {
					break;
				}
				/* Dynamically compute the eflags (like REG_NOTBOL) based on offset. */
				const int eflags_curr = G.eflags | jstr_internal_re_notbol(buf->data, off, G.regex.cflags);
				regmatch_t rm[10];
				memset(rm, 0, sizeof(rm));
				const int ret = jstr_re_exec_len(&G.regex, buf->data + off, scan_size - off, 10, rm, eflags_curr);
				if (ret == JSTR_RE_RET_NOERROR) {
					const size_t match_len = (size_t)(rm[0].rm_eo - rm[0].rm_so);
					const size_t m_start = off + (size_t)rm[0].rm_so;
					const size_t m_end = off + (size_t)rm[0].rm_eo;
					match_pushback(&G.matches, m_start, m_end, rm);
					--n;
					/* Set the next search pointer to the end of the match. */
					size_t next_src = m_end;
					/*
					 * If the match was zero-length (e.g. ^$ or empty group), advance
					 * past one character to prevent infinite loops, copying that character plain.
					 */
					if (match_len == 0) {
						if (next_src < scan_size) {
							++next_src;
						}
					}
					off = next_src;
					/* If the match occurred at the end of the string, stop immediately. */
					if (matched_at_end)
						break;
					prev_zero = (match_len == 0);
				} else if (ret == JSTR_RE_RET_NOMATCH) {
					break;
				} else {
					break;
				}
			}
		}
	} else {
		if (find_len > 0) {
			/* Fixed-string pass uses the precompiled Two-Way matcher. */
			for (size_t off = 0; off < buf->size; ) {
				const char *const p = (const char *)jstr_memmem_exec(t, buf->data + off, buf->size - off, find, find_len);
				if (p == NULL)
					break;
				const size_t m_start = (size_t)JSTR_PTR_DIFF(p, buf->data);
				const size_t m_end = m_start + find_len;
				match_pushback(&G.matches, m_start, m_end, NULL);
				if (G.n == 1)
					break;
				off = m_end;
			}
		}
	}
	if (G.matches.size > 0) {
		G.matches_found = 1;
		/* Merge all matches that lie on the same line into a single block so
		 * each changed source line is shown once. */
		line_counter_ty lc;
		line_counter_init(&lc, buf->data);
		ptrdiff_t new_shift = 0;
		size_t i = 0;
		while (i < G.matches.size) {
			/* Group consecutive matches that lie on the same line into one block. */
			size_t j = i;
			while (j + 1 < G.matches.size && line_get_start(buf->data, buf->size, G.matches.data[j + 1].start) <= match_line_end(buf->data, buf->size, G.matches.data[j].start, G.matches.data[j].end))
				++j;
			const size_t block_start = line_get_start(buf->data, buf->size, G.matches.data[i].start);
			const size_t block_end = match_line_end(buf->data, buf->size, G.matches.data[j].start, G.matches.data[j].end);
			const size_t line = line_counter_get(&lc, G.matches.data[i].start);
			/* Build the replacement content for this block into NEW_BUF. */
			jstr_empty_j(&G.new_buf);
			size_t p = block_start;
			for (size_t k = i; k <= j; ++k) {
				if (G.matches.data[k].start > p)
					DIE_IF(jstr_chk(jstr_append_len_j(&G.new_buf, buf->data + p, G.matches.data[k].start - p)), "%s", "Out of memory.\n");
				if (G.mode & MODE_USE_REGEX && backref) {
					size_t rplcwbackref_len = jstr_internal_re_rplcbackrefstrlen(G.matches.data[k].rm, rplc_backref1, rplc_backref1_e, rplc_len);
					jstr_empty_j(&G.rplc_buf);
					DIE_IF(jstr_reserve_j(&G.rplc_buf, rplcwbackref_len + 1), "%s", "Out of memory.\n");
					DIE_IF(!G.rplc_buf.data, "%s", "Out of memory allocating replacement buffer.\n");
					const unsigned char *mtc_src = (const unsigned char *)buf->data + G.matches.data[k].start - G.matches.data[k].rm[0].rm_so;
					jstr_internal_re_rplcbackrefcpy(G.matches.data[k].rm, mtc_src, (unsigned char *)G.rplc_buf.data, (const unsigned char *)rplc, (const unsigned char *)rplc + rplc_len);
					DIE_IF(jstr_chk(jstr_append_len_j(&G.new_buf, G.rplc_buf.data, rplcwbackref_len)), "%s", "Out of memory.\n");
				} else {
					DIE_IF(jstr_chk(jstr_append_len_j(&G.new_buf, rplc, rplc_len)), "%s", "Out of memory.\n");
				}
				p = G.matches.data[k].end;
			}
			if (block_end > p)
				DIE_IF(jstr_chk(jstr_append_len_j(&G.new_buf, buf->data + p, block_end - p)), "%s", "Out of memory.\n");
			/* Old side is the untouched block; new side is the built replacement.
			 * BLOCK never ends in the last changed line's own terminator: when the
			 * match consumed that '\n' it is excluded and TRAILING_NL is 0, when it
			 * survives TRAILING_NL is 1. A replacement that ends in '\n' (or is
			 * empty) therefore renders the empty line that follows it exactly when
			 * the block's terminating newline survives, matching how diff counts
			 * lines. */
			int trailing_nl;
			if (G.matches.data[j].end > G.matches.data[j].start && buf->data[G.matches.data[j].end - 1] == '\n')
				trailing_nl = 0;
			else
				trailing_nl = (block_end < buf->size);
			const size_t old_len = block_end - block_start;
			const size_t old_count = jstr_countchr_len(buf->data + block_start, '\n', old_len) + 1;
			size_t new_count = jstr_countchr_len(G.new_buf.data, '\n', G.new_buf.size);
			if (G.new_buf.size > 0 && G.new_buf.data[G.new_buf.size - 1] != '\n')
				++new_count;
			if (trailing_nl && (G.new_buf.size == 0 || G.new_buf.data[G.new_buf.size - 1] == '\n'))
				++new_count;
			/* The "+" side's start line numbers the new file, shifted by the
			 * net change of every previous block. */
			ptrdiff_t new_line = (ptrdiff_t)line + new_shift;
			if (new_line < 1)
				new_line = 1;
			print_diff_lines(buf->data + block_start, old_len, '-', S_LITERAL(COLOR_RED), fname, fname_len, line, old_len == 0);
			print_diff_lines(G.new_buf.data, G.new_buf.size, '+', S_LITERAL(COLOR_GREEN), fname, fname_len, (size_t)new_line, trailing_nl);
			new_shift += (ptrdiff_t)new_count - (ptrdiff_t)old_count;
			i = j + 1;
		}
	}
	*out_matches = G.matches.size;
	return JSTR_RET_SUCC;
}
