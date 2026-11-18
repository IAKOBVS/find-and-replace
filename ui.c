/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "ui.h"
#include "terminal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include "procfs.h"
#endif

#define PREVIEW_MATCH_BUDGET_FACTOR 4
#define FREE_RAM_FALLBACK (1 * JSTR_IO_GIB)
#define MEMINFO_BUF_SIZE (4096 + 1)
#define RANGES_CAP_MIN 1

jstr_ret_ty
ui_replaced_buf(const char *R data, size_t size)
{
	if (jstr_unlikely(jstr_io_fwrite(data, 1, size, stdout) != size))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_SUCC;
}

jstr_ret_ty
ui_report_changed(const char *R fname, size_t fname_len)
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

static jstr_ret_ty
ui_append(jstr_ty *R out, const char *R data, size_t size)
{
	if (jstr_chk(jstr_append_len_j(out, data, size)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_SUCC;
}

static jstr_ret_ty
ui_append_char(jstr_ty *R out, char c)
{
	if (jstr_chk(jstr_pushback_j(out, c)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_SUCC;
}

static jstr_ret_ty
ui_append_line_number(jstr_ty *R out, size_t val)
{
	char buf[32];
	size_t i = sizeof buf;
	do {
		buf[--i] = (char)('0' + val % 10);
		val /= 10;
	} while (val > 0);
	return ui_append(out, buf + i, sizeof buf - i);
}

jstr_ret_ty
ui_format_grep_line(jstr_ty *R out, const char *R fname, size_t fname_len,
                    size_t line, const char *R data, size_t size,
                    size_t match_off, size_t match_len)
{
	if (jstr_likely(fname != NULL)) {
		if (jstr_chk(ui_append(out, S_LITERAL(TUI_GREP_FILENAME))) ||
		    jstr_chk(ui_append(out, fname, fname_len)) ||
		    jstr_chk(ui_append(out, S_LITERAL(TUI_GREP_UNMATCHED))) ||
		    jstr_chk(ui_append_char(out, ':')))
			goto err;
	}
	if (jstr_chk(ui_append(out, S_LITERAL(TUI_GREP_LINENUMBER))) ||
	    jstr_chk(ui_append_line_number(out, line)) ||
	    jstr_chk(ui_append(out, S_LITERAL(TUI_GREP_UNMATCHED))) ||
	    jstr_chk(ui_append_char(out, ':')) ||
	    jstr_chk(ui_append(out, data, match_off)) ||
	    jstr_chk(ui_append(out, S_LITERAL(TUI_GREP_MATCHED))) ||
	    jstr_chk(ui_append(out, data + match_off, match_len)) ||
	    jstr_chk(ui_append(out, S_LITERAL(TUI_GREP_UNMATCHED))) ||
	    jstr_chk(ui_append(out, data + match_off + match_len, size - match_off - match_len)) ||
	    jstr_chk(ui_append_char(out, '\n')))
		goto err;
	return JSTR_RET_SUCC;
err:
	return JSTR_RET_ERR;
}

jstr_ret_ty
ui_result(far_result_ty *R res, const args_ty *R a)
{
	if (G.mode & MODE_GREP) {
		if (res->pr.matched)
			G.grep_matched = 1;
		if (res->path != NULL && G.grep_collect) {
			if (res->pr.out != NULL)
				ui_file_pushback(&G.files, res->path, res->path_len, &res->pr.st, res->pr.out);
		} else if (res->pr.matched && res->pr.out != NULL) {
			if (!(G.mode & MODE_QUIET))
				if (jstr_chk(ui_replaced_buf(res->pr.out->data, res->pr.out->size)))
					JSTR_RETURN_ERR(JSTR_RET_ERR);
		}
		return JSTR_RET_SUCC;
	}
	if (G.confirm_pass && (G.mode & MODE_CONFIRM)) {
		if (res->pr.out != NULL) {
			if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
				ui_file_pushback(&G.files, res->path, res->path_len, &res->pr.st, res->pr.out);
			} else {
				size_t matches = 0;
				if (jstr_chk(ui_scan_file(a->t, res->pr.out, res->path,
				                         res->path_len, a->find, a->find_len,
				                         a->rplc, a->rplc_len, &matches)))
					JSTR_RETURN_ERR(JSTR_RET_ERR);
				if (matches > 0)
					ui_file_pushback(&G.files, res->path, res->path_len, &res->pr.st, res->pr.out);
			}
		}
		return JSTR_RET_SUCC;
	}
	if (G.mode & MODE_PRINT_STDOUT) {
		if (res->pr.out != NULL)
			if (jstr_chk(ui_replaced_buf(res->pr.out->data, res->pr.out->size)))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		return JSTR_RET_SUCC;
	}
	if (res->pr.report)
		if (jstr_chk(ui_report_changed(res->path, res->path_len)))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_SUCC;
}

void
ui_result_free(far_result_ty *R res)
{
	if (res->pr.out != NULL) {
		jstr_free_j(res->pr.out);
		free(res->pr.out);
	}
	free(res->path);
	free(res);
}

void
ui_grep_line(const char *R fname, size_t fname_len, size_t line,
               const char *R data, size_t size,
               size_t match_off, size_t match_len)
{
	if (jstr_likely(fname != NULL)) {
		(void)jstr_io_fwrite(TUI_GREP_FILENAME, 1, S_LEN(TUI_GREP_FILENAME), stdout);
		(void)jstr_io_fwrite(fname, 1, fname_len, stdout);
		(void)jstr_io_fwrite(TUI_GREP_UNMATCHED, 1, S_LEN(TUI_GREP_UNMATCHED), stdout);
		(void)jstr_io_fputc(':', stdout);
	}
	(void)jstr_io_fwrite(TUI_GREP_LINENUMBER, 1, S_LEN(TUI_GREP_LINENUMBER), stdout);
	ui_print_size_t(line);
	(void)jstr_io_fwrite(TUI_GREP_UNMATCHED, 1, S_LEN(TUI_GREP_UNMATCHED), stdout);
	(void)jstr_io_fputc(':', stdout);
	(void)jstr_io_fwrite(data, 1, match_off, stdout);
	(void)jstr_io_fwrite(TUI_GREP_MATCHED, 1, S_LEN(TUI_GREP_MATCHED), stdout);
	(void)jstr_io_fwrite(data + match_off, 1, match_len, stdout);
	(void)jstr_io_fwrite(TUI_GREP_UNMATCHED, 1, S_LEN(TUI_GREP_UNMATCHED), stdout);
	(void)jstr_io_fwrite(data + match_off + match_len, 1, size - match_off - match_len, stdout);
	(void)jstr_io_fputc('\n', stdout);
}

int
ui_ok(void)
{
	return !ferror(stdout);
}

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
	if (rm)
		memcpy((matches->data)[matches->size].rm, rm, JSTR_NMATCH_MAX * sizeof(regmatch_t));
	else
		memset((matches->data)[matches->size].rm, 0, JSTR_NMATCH_MAX * sizeof(regmatch_t));
	++matches->size;
}

static size_t
get_free_ram_size(void)
{
#ifdef __linux__
	const int fd = open("/proc/meminfo", O_RDONLY);
	if (jstr_unlikely(fd == -1))
		return FREE_RAM_FALLBACK;

	char buf[MEMINFO_BUF_SIZE];
	const ssize_t read_sz = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (jstr_unlikely(read_sz <= 0))
		return FREE_RAM_FALLBACK;

	buf[read_sz] = '\0';

	struct procfs_iter iter;
	procfs_iter_init(&iter, buf, (unsigned int)read_sz);

	const char *key;
	const char *val;
	unsigned int key_len;
	unsigned int val_len;

	size_t free_ram = 0;
	while (procfs_iter_next(&iter, &key, &key_len, &val, &val_len, ':')) {
		if (key_len == S_LEN("MemAvailable") && memcmp(key, S_LITERAL("MemAvailable")) == 0) {
			free_ram = (size_t)strtoul(val, NULL, 10) * JSTR_IO_KIB;
			break;
		}
	}

	return free_ram ? free_ram : FREE_RAM_FALLBACK;
#else
	return 1 * JSTR_IO_GIB;
#endif
}

static size_t
get_file_cache_max(void)
{
	if (G.file_cache_max == 0) {
		size_t free_ram = get_free_ram_size();
		G.file_cache_max = free_ram / 2;
	}
	return G.file_cache_max;
}

/* Append one file to the -c confirm cache. The name is strdup'd because
 * ftw->dirpath is a transient buffer reused across callbacks; the content
 * buffer is stolen from the shared buf so pass 2 needs no disk I/O. */
void
ui_file_pushback(files_ty *files,
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
	file->has_match = 0;
	/* Take ownership of the already-read content and reset the shared buffer. */
	if (jstr_likely(files->total_content_size < get_file_cache_max())) {
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

unsigned short
ui_size_t_width(size_t val)
{
	if (val == 0)
		return 1;
	unsigned short width = 0;
	while (val > 0) {
		width++;
		val /= 10;
	}
	return width;
}

/* Write VAL in decimal to stdout without using printf. */
void
ui_print_size_t(size_t val)
{
	if (jstr_unlikely(!ui_ok()))
		return;
	char buf[3 * sizeof(val) + 2];
	size_t i = sizeof(buf);
	if (val == 0)
		buf[--i] = '0';
	while (val > 0) {
		buf[--i] = (char)('0' + val % 10);
		val /= 10;
	}
	(void)jstr_io_fwrite(buf + i, 1, sizeof(buf) - i, stdout);
}

/* Print the "FNAME:LINE:" prefix of one -c preview line. FNAME_COLOR tints
 * the file name (wrapped in inverse video when IS_SELECTED); LINE_COLOR tints
 * the line number; colons are unmatched. */
static void
print_line_prefix(const char *R fname, size_t fname_len, size_t line, int is_selected,
                  const char *fname_color, unsigned int fname_color_len,
                  const char *line_color, unsigned int line_color_len)
{
	if (jstr_unlikely(!ui_ok()))
		return;
	(void)jstr_io_fwrite(fname_color, 1, fname_color_len, stdout);
	if (is_selected)
		(void)jstr_io_fwrite(COLOR_NEGATIVE, 1, S_LEN(COLOR_NEGATIVE), stdout);
	(void)jstr_io_fwrite(fname, 1, fname_len, stdout);
	if (is_selected)
		(void)jstr_io_fwrite(COLOR_POSITIVE, 1, S_LEN(COLOR_POSITIVE), stdout);
	(void)jstr_io_fwrite(TUI_CONFIRM_UNMATCHED, 1, S_LEN(TUI_CONFIRM_UNMATCHED), stdout);
	(void)jstr_io_putchar(':');
	(void)jstr_io_fwrite(line_color, 1, line_color_len, stdout);
	ui_print_size_t(line);
	(void)jstr_io_fwrite(TUI_CONFIRM_UNMATCHED, 1, S_LEN(TUI_CONFIRM_UNMATCHED), stdout);
	(void)jstr_io_putchar(':');
}

/* Print S of LEN bytes, expanding tab characters to 8-column stops and
 * truncating/clipping to COLS - 1 columns. COL_PTR tracks the current column
 * (0-indexed). */
void
ui_print_diff_line_chars(const char *s, size_t len, unsigned short cols, unsigned short *col_ptr)
{
	if (jstr_unlikely(!ui_ok()))
		return;
	unsigned short col = *col_ptr;
	unsigned short limit = (cols > 1) ? (cols - 1) : 0;
	for (size_t i = 0; i < len; ++i) {
		char c = s[i];
		if (c == '\t') {
			unsigned short next_tab = (unsigned short)((col + 8) & ~7);
			while (col < next_tab) {
				if (col < limit)
					(void)jstr_io_putchar(' ');
				col++;
			}
		} else {
			if (col < limit)
				(void)jstr_io_putchar(c);
			col++;
		}
	}
	*col_ptr = col;
}

/* Print one side of a -c preview change: each line of DATA is printed on its
 * own line as "FNAME:LINE:<content>"; FNAME_COLOR tints the file name,
 * LINE_COLOR the line number, and MATCH_COLOR the matched ranges in RANGES;
 * everything else is unmatched. DATA covers the block from the start of
 * the first changed line up to (but not including) the '\n' that terminates
 * the last changed line; START_LINE is the line number of the first emitted line.
 * TRAILING_NL is set when that terminating '\n' exists. */
static void
print_diff_lines(const char *R data, size_t len, const range_ty *ranges, size_t num_ranges,
                    const char *fname_color, unsigned int fname_color_len,
                    const char *line_color, unsigned int line_color_len,
                    const char *match_color, unsigned int match_color_len,
                    const char *R fname, size_t fname_len, size_t start_line, int trailing_nl)
{
	if (jstr_unlikely(!ui_ok()))
		return;
	const char *p = data;
	const char *const end = data + len;
	size_t line = start_line;
	const char *nl;
	unsigned short cols = 0;
	const size_t vis_end = G.scroll_offset + G.max_preview_lines;
	const int has_scroll = terminal_active() && (G.scroll_offset > 0 || G.total_lines > G.max_preview_lines);
	if (terminal_active())
		cols = terminal_cols();
	int render = 1;
	size_t r_idx = 0;

	while ((nl = (const char *)memchr(p, '\n', (size_t)(end - p))) != NULL) {
		if (render && terminal_active() && G.max_preview_lines > 0 && G.preview_lines_printed >= vis_end)
			render = 0;
		if (!render) {
			G.preview_lines_printed++;
			p = nl + 1;
			continue;
		}
		if (has_scroll && G.preview_lines_printed < G.scroll_offset) {
			G.preview_lines_printed++;
			p = nl + 1;
			continue;
		}

		print_line_prefix(fname, fname_len, line++, G.preview_lines_printed == G.selected_line, fname_color, fname_color_len, line_color, line_color_len);

		unsigned short col = 0;
		if (terminal_active())
			col = (unsigned short)(fname_len + ui_size_t_width(line - 1) + 2);

		size_t line_start_off = (size_t)JSTR_PTR_DIFF(p, data);
		size_t line_end_off = (size_t)JSTR_PTR_DIFF(nl, data);
		size_t curr = line_start_off;
		int in_highlight = 0;

		while (curr < line_end_off) {
			while (r_idx < num_ranges && ranges[r_idx].end <= curr)
				r_idx++;

			size_t next_boundary = line_end_off;
			int want_highlight = 0;

			if (r_idx < num_ranges && ranges[r_idx].start < line_end_off) {
				if (ranges[r_idx].start > curr) {
					next_boundary = ranges[r_idx].start;
					want_highlight = 0;
				} else {
					next_boundary = (ranges[r_idx].end < line_end_off) ? ranges[r_idx].end : line_end_off;
					want_highlight = (ranges[r_idx].end > ranges[r_idx].start);
				}
			}

			if (want_highlight != in_highlight) {
				if (want_highlight)
					(void)jstr_io_fwrite(match_color, 1, match_color_len, stdout);
				else
					(void)jstr_io_fwrite(TUI_CONFIRM_UNMATCHED, 1, S_LEN(TUI_CONFIRM_UNMATCHED), stdout);
				in_highlight = want_highlight;
			}

			size_t seg_len = next_boundary - curr;
			if (terminal_active())
				ui_print_diff_line_chars(data + curr, seg_len, cols, &col);
			else
				(void)jstr_io_fwrite(data + curr, 1, seg_len, stdout);

			curr = next_boundary;
		}

		if (in_highlight)
			(void)jstr_io_fwrite(TUI_CONFIRM_UNMATCHED, 1, S_LEN(TUI_CONFIRM_UNMATCHED), stdout);
		if (terminal_active())
			(void)jstr_io_fwrite(ANSI_CLEAR_LINE_END, 1, S_LEN(ANSI_CLEAR_LINE_END), stdout);
		(void)jstr_io_putchar('\n');
		if (terminal_active())
			G.preview_lines_printed++;
		p = nl + 1;
	}

	if (p < end) {
		if (render && terminal_active() && G.max_preview_lines > 0 && G.preview_lines_printed >= vis_end)
			render = 0;
		if (!render) {
			G.preview_lines_printed++;
		} else if (has_scroll && G.preview_lines_printed < G.scroll_offset) {
			G.preview_lines_printed++;
		} else {
			print_line_prefix(fname, fname_len, line, G.preview_lines_printed == G.selected_line, fname_color, fname_color_len, line_color, line_color_len);

			unsigned short col = 0;
			if (terminal_active())
				col = (unsigned short)(fname_len + ui_size_t_width(line) + 2);

			size_t line_start_off = (size_t)JSTR_PTR_DIFF(p, data);
			size_t line_end_off = (size_t)JSTR_PTR_DIFF(end, data);
			size_t curr = line_start_off;
			int in_highlight = 0;

			while (curr < line_end_off) {
				while (r_idx < num_ranges && ranges[r_idx].end <= curr)
					r_idx++;

				size_t next_boundary = line_end_off;
				int want_highlight = 0;

				if (r_idx < num_ranges && ranges[r_idx].start < line_end_off) {
					if (ranges[r_idx].start > curr) {
						next_boundary = ranges[r_idx].start;
						want_highlight = 0;
					} else {
						next_boundary = (ranges[r_idx].end < line_end_off) ? ranges[r_idx].end : line_end_off;
						want_highlight = (ranges[r_idx].end > ranges[r_idx].start);
					}
				}

				if (want_highlight != in_highlight) {
					if (want_highlight)
						(void)jstr_io_fwrite(match_color, 1, match_color_len, stdout);
					else
						(void)jstr_io_fwrite(TUI_CONFIRM_UNMATCHED, 1, S_LEN(TUI_CONFIRM_UNMATCHED), stdout);
					in_highlight = want_highlight;
				}

				size_t seg_len = next_boundary - curr;
				if (terminal_active())
					ui_print_diff_line_chars(data + curr, seg_len, cols, &col);
				else
					(void)jstr_io_fwrite(data + curr, 1, seg_len, stdout);

				curr = next_boundary;
			}

			if (in_highlight)
				(void)jstr_io_fwrite(TUI_CONFIRM_UNMATCHED, 1, S_LEN(TUI_CONFIRM_UNMATCHED), stdout);
			if (terminal_active())
				(void)jstr_io_fwrite(ANSI_CLEAR_LINE_END, 1, S_LEN(ANSI_CLEAR_LINE_END), stdout);
			(void)jstr_io_putchar('\n');
			if (terminal_active())
				G.preview_lines_printed++;
		}
	} else if (trailing_nl) {
		if (render && terminal_active() && G.max_preview_lines > 0 && G.preview_lines_printed >= vis_end)
			render = 0;
		if (!render) {
			G.preview_lines_printed++;
		} else if (has_scroll && G.preview_lines_printed < G.scroll_offset) {
			G.preview_lines_printed++;
		} else {
			print_line_prefix(fname, fname_len, line, G.preview_lines_printed == G.selected_line, fname_color, fname_color_len, line_color, line_color_len);
			if (terminal_active())
				(void)jstr_io_fwrite(ANSI_CLEAR_LINE_END, 1, S_LEN(ANSI_CLEAR_LINE_END), stdout);
			(void)jstr_io_putchar('\n');
			if (terminal_active())
				G.preview_lines_printed++;
		}
	}
}

static void
confirm_scan_regex_matches(const jstr_ty *R buf, size_t find_len, size_t match_budget)
{
	if (find_len == 0)
		return;
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
		regmatch_t rm[JSTR_NMATCH_MAX];
		memset(rm, 0, sizeof(rm));
		const int ret = jstr_re_exec_len(&G.regex, buf->data + off, scan_size - off, JSTR_NMATCH_MAX, rm, eflags_curr);
		if (ret == JSTR_RE_RET_NOERROR) {
			const size_t match_len = (size_t)(rm[0].rm_eo - rm[0].rm_so);
			const size_t m_start = off + (size_t)rm[0].rm_so;
			const size_t m_end = off + (size_t)rm[0].rm_eo;
			if (jstr_unlikely(G.matches.size >= match_budget)) {
				G.preview_full = 1;
				break;
			}
			match_pushback(&G.matches, m_start, m_end, rm);
			--n;
			/* Set the next search pointer to the end of the match. */
			size_t next_src = m_end;
			/*
			 * If the match was zero-length (e.g. ^$ or empty group), advance
			 * past one character to prevent infinite loops, copying that character plain.
			 */
			if (match_len == 0)
				if (next_src < scan_size)
					++next_src;
			off = next_src;
			/* If the match occurred at the end of the string, stop immediately. */
			if (matched_at_end)
				break;
			prev_zero = (match_len == 0);
		} else {
			break;
		}
	}
}

static void
confirm_scan_fixed_matches(const jstr_twoway_ty *R t, const jstr_ty *R buf, const char *R find, size_t find_len, size_t match_budget)
{
	if (find_len == 0)
		return;
	/* Fixed-string pass uses the precompiled Two-Way matcher. */
	for (size_t off = 0; off < buf->size; ) {
		const char *const p = (const char *)jstr_memmem_exec(t, buf->data + off, buf->size - off, find, find_len);
		if (p == NULL)
			break;
		const size_t m_start = (size_t)JSTR_PTR_DIFF(p, buf->data);
		const size_t m_end = m_start + find_len;
		if (jstr_unlikely(G.matches.size >= match_budget)) {
			G.preview_full = 1;
			break;
		}
		match_pushback(&G.matches, m_start, m_end, NULL);
		if (G.n == 1)
			break;
		off = m_end;
	}
}

static jstr_ret_ty
ranges_reserve(ranges_ty *ranges, size_t required_size)
{
	if (ranges->cap < required_size) {
		if (ranges->cap == 0)
			ranges->cap = RANGES_CAP_MIN;
		while (ranges->cap < required_size)
			ranges->cap *= 2;
		range_ty *const new_data = (range_ty *)realloc(ranges->data, ranges->cap * sizeof(range_ty));
		if (jstr_unlikely(new_data == NULL))
			return JSTR_RET_ERR;
		ranges->data = new_data;
	}
	ranges->size = required_size;
	return JSTR_RET_SUCC;
}

jstr_ret_ty
ui_scan_file(const jstr_twoway_ty *R t,
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
	G.matches.size = 0;
	const size_t match_budget = (G.max_preview_lines > 0) ? (size_t)G.max_preview_lines * PREVIEW_MATCH_BUDGET_FACTOR : SIZE_MAX;
	if (G.mode & MODE_USE_REGEX)
		confirm_scan_regex_matches(buf, find_len, match_budget);
	else
		confirm_scan_fixed_matches(t, buf, find, find_len, match_budget);
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
			/* Build the replacement content for this block into NEW_BUF,
			 * tracking match ranges for old block and replacement ranges for new block. */
			jstr_empty_j(&G.new_buf);
			size_t num_block_matches = j - i + 1;
			G.old_ranges.size = 0;
			G.new_ranges.size = 0;
			ranges_reserve(&G.old_ranges, num_block_matches);
			ranges_reserve(&G.new_ranges, num_block_matches);
			size_t p = block_start;
			for (size_t k = i; k <= j; ++k) {
				size_t idx = k - i;
				G.old_ranges.data[idx].start = G.matches.data[k].start - block_start;
				G.old_ranges.data[idx].end = G.matches.data[k].end - block_start;

				if (G.matches.data[k].start > p)
					DIE_IF(jstr_chk(jstr_append_len_j(&G.new_buf, buf->data + p, G.matches.data[k].start - p)), "%s", "Out of memory.\n");

				G.new_ranges.data[idx].start = G.new_buf.size;

				if (G.mode & MODE_USE_REGEX && backref) {
					size_t rplcwbackref_len = jstr_internal_re_rplcbackrefstrlen(G.matches.data[k].rm, rplc_backref1, rplc_backref1_e, rplc_len, JSTR_NMATCH_MAX);
					jstr_empty_j(&G.rplc_buf);
					DIE_IF(jstr_chk(jstr_reserve_j(&G.rplc_buf, rplcwbackref_len + 1)), "%s", "Out of memory.\n");
					DIE_IF(!G.rplc_buf.data, "%s", "Out of memory allocating replacement buffer.\n");
					const unsigned char *mtc_src = (const unsigned char *)buf->data + G.matches.data[k].start - G.matches.data[k].rm[0].rm_so;
					jstr_internal_re_rplcbackrefcpy(G.matches.data[k].rm, mtc_src, (unsigned char *)G.rplc_buf.data, (const unsigned char *)rplc, (const unsigned char *)rplc + rplc_len, JSTR_NMATCH_MAX);
					DIE_IF(jstr_chk(jstr_append_len_j(&G.new_buf, G.rplc_buf.data, rplcwbackref_len)), "%s", "Out of memory.\n");
				} else {
					DIE_IF(jstr_chk(jstr_append_len_j(&G.new_buf, rplc, rplc_len)), "%s", "Out of memory.\n");
				}

				G.new_ranges.data[idx].end = G.new_buf.size;
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
			print_diff_lines(buf->data + block_start, old_len, G.old_ranges.data, num_block_matches, S_LITERAL(TUI_CONFIRM_FILENAME_REMOVED), S_LITERAL(TUI_CONFIRM_LINENUMBER_REMOVED), S_LITERAL(TUI_CONFIRM_MATCHED_REMOVED), fname, fname_len, line, old_len == 0);
			print_diff_lines(G.new_buf.data, G.new_buf.size, G.new_ranges.data, num_block_matches, S_LITERAL(TUI_CONFIRM_FILENAME_ADDED), S_LITERAL(TUI_CONFIRM_LINENUMBER_ADDED), S_LITERAL(TUI_CONFIRM_MATCHED_ADDED), fname, fname_len, (size_t)new_line, trailing_nl);
			new_shift += (ptrdiff_t)new_count - (ptrdiff_t)old_count;
			i = j + 1;
		}
	}
	*out_matches = G.matches.size;
	return JSTR_RET_SUCC;
}


