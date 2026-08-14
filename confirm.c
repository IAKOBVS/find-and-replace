/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "confirm.h"
#include "files.h"
#include <termios.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#ifdef __linux__
struct b_proc_iter {
	const char *pos;
	const char *end;
};

static void
b_proc_iter_init(struct b_proc_iter *iter, const char *buf, unsigned int len)
{
	iter->pos = buf;
	iter->end = buf + len;
}

static int
b_proc_iter_next(struct b_proc_iter *iter, const char **key, unsigned int *key_len, const char **val, unsigned int *val_len, int delimiter)
{
	while (iter->pos < iter->end) {
		const char *line_start = iter->pos;
		const char *line_end = (const char *)memchr(line_start, '\n', (size_t)(iter->end - line_start));
		if (line_end == NULL) {
			line_end = iter->end;
			iter->pos = iter->end;
		} else {
			iter->pos = line_end + 1;
		}

		const char *delim_pos = (const char *)memchr(line_start, delimiter, (size_t)(line_end - line_start));
		if (delim_pos == NULL)
			continue;

		const char *k_start = line_start;
		const char *k_end = delim_pos;
		while (k_start < k_end && *k_start == ' ')
			k_start++;
		while (k_end > k_start && *(k_end - 1) == ' ')
			k_end--;

		const char *v_start = delim_pos + 1;
		const char *v_end = line_end;
		while (v_start < v_end && *v_start == ' ')
			v_start++;
		while (v_end > v_start && *(v_end - 1) == ' ')
			v_end--;

		*key = k_start;
		*key_len = (unsigned int)(k_end - k_start);
		*val = v_start;
		*val_len = (unsigned int)(v_end - v_start);
		return 1;
	}
	return 0;
}
#endif

static struct termios orig_termios;
static int term_initialized = 0;

static void
restore_terminal(void)
{
	if (term_initialized) {
		tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
		/* Use async-signal-safe write for signal safety when leaving alt screen and showing cursor */
		if (jstr_unlikely(write(STDOUT_FILENO, "\x1b[?1049l\x1b[?25h", 14) < 0)) {}
		term_initialized = 0;
	}
}

static void
handle_signal(int sig)
{
	(void)sig;
	restore_terminal();
	_exit(EXIT_FAILURE);
}

static void
setup_terminal(void)
{
	if (jstr_unlikely(!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)))
		return;
	if (jstr_unlikely(tcgetattr(STDIN_FILENO, &orig_termios) < 0))
		return;
	struct termios raw = orig_termios;
	raw.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
	raw.c_iflag &= ~(IXON | ICRNL);
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;
	if (jstr_unlikely(tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0))
		return;
	term_initialized = 1;
	/* Use 21 (or S_LEN) so the entire escape sequence is written, clearing screen and hiding the cursor properly */
	jstr_io_fwrite("\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l", 1, 21, stdout); /* enter alt screen, clear/home, hide cursor */
	jstr_io_fflush(stdout);
	atexit(restore_terminal);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGQUIT, handle_signal);
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
	if (rm) {
		memcpy((matches->data)[matches->size].rm, rm, 10 * sizeof(regmatch_t));
	} else {
		memset((matches->data)[matches->size].rm, 0, 10 * sizeof(regmatch_t));
	}
	++matches->size;
}

static size_t
get_free_ram_size(void)
{
#ifdef __linux__
	const int fd = open("/proc/meminfo", O_RDONLY);
	if (jstr_unlikely(fd == -1))
		return 1 * JSTR_IO_GIB;

	char buf[4096];
	const ssize_t read_sz = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (jstr_unlikely(read_sz <= 0))
		return 1 * JSTR_IO_GIB;

	buf[read_sz] = '\0';

	struct b_proc_iter iter;
	b_proc_iter_init(&iter, buf, (unsigned int)read_sz);

	const char *key;
	const char *val;
	unsigned int key_len;
	unsigned int val_len;

	size_t free_ram = 0;
	while (b_proc_iter_next(&iter, &key, &key_len, &val, &val_len, ':')) {
		if (key_len == 7 && memcmp(key, "MemFree", 7) == 0) {
			free_ram = (size_t)strtoul(val, NULL, 10) * JSTR_IO_KIB;
			break;
		}
	}

	return free_ram;
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
		if (term_initialized && G.max_preview_lines > 0 && G.preview_lines_printed >= G.max_preview_lines) {
			jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
			return;
		}
		print_line_prefix(fname, fname_len, line++, prefix);
		jstr_io_fwrite(p, 1, (size_t)(nl - p), stdout);
		if (term_initialized)
			jstr_io_fwrite("\x1b[K", 1, 3, stdout);
		jstr_io_putchar('\n');
		if (term_initialized)
			G.preview_lines_printed++;
		p = nl + 1;
	}
	if (p < end) {
		if (term_initialized && G.max_preview_lines > 0 && G.preview_lines_printed >= G.max_preview_lines) {
			jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
			return;
		}
		/* The final line is not newline-terminated: print it as-is. */
		print_line_prefix(fname, fname_len, line, prefix);
		jstr_io_fwrite(p, 1, (size_t)(end - p), stdout);
		if (term_initialized)
			jstr_io_fwrite("\x1b[K", 1, 3, stdout);
		jstr_io_putchar('\n');
		if (term_initialized)
			G.preview_lines_printed++;
	} else if (trailing_nl) {
		if (term_initialized && G.max_preview_lines > 0 && G.preview_lines_printed >= G.max_preview_lines) {
			jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
			return;
		}
		/* DATA ended in '\n' (or is empty): the empty line that follows the
		 * block survives only when the block's terminating '\n' does. */
		print_line_prefix(fname, fname_len, line, prefix);
		if (term_initialized)
			jstr_io_fwrite("\x1b[K", 1, 3, stdout);
		jstr_io_putchar('\n');
		if (term_initialized)
			G.preview_lines_printed++;
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

static jstr_ret_ty
interactive_compile(jstr_twoway_ty *t, const char *find, size_t find_len, const char *rplc, size_t rplc_len, char *err_buf, size_t err_size)
{
	if (G.mode & MODE_USE_REGEX) {
		if (G.mode & MODE_COMPILED) {
			jstr_re_free(&G.regex);
			G.mode &= ~MODE_COMPILED;
		}
		const int ret = jstr_re_comp(&G.regex, find, G.cflags);
		if (jstr_unlikely(ret != JSTR_RE_RET_NOERROR)) {
			regerror(ret, &G.regex.reg, err_buf, err_size);
			return JSTR_RET_ERR;
		}
		G.mode |= MODE_COMPILED;

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
		if (max_backref > G.regex.reg.re_nsub) {
			snprintf(err_buf, err_size, "Replace backreference \\%zu exceeds find capture groups (%zu)", max_backref, G.regex.reg.re_nsub);
			return JSTR_RET_ERR;
		}
	} else {
		jstr_memmem_comp(t, find, find_len);
	}
	return JSTR_RET_SUCC;
}

typedef enum {
	FIELD_FIND,
	FIELD_RPLC,
	FIELD_FLAGS,
	FIELD_FILES,
	FIELD_COUNT
} field_ty;

static void
parse_interactive_flags(const char *flags, size_t len)
{
	/* Reset to initial configuration default states */
	G.n = 1;
	G.mode &= ~MODE_USE_REGEX;
	G.cflags &= ~(JSTR_RE_CF_EXTENDED | JSTR_RE_CF_ICASE);
	G.cflags |= JSTR_RE_CF_NEWLINE;

	for (size_t idx = 0; idx < len; ++idx) {
		char f = flags[idx];
		switch (f) {
		case 'g':
			G.n = (size_t)-1;
			break;
		case 'G':
			G.n = 1;
			break;
		case 'R':
			G.mode |= MODE_USE_REGEX;
			break;
		case 'F':
			G.mode &= ~MODE_USE_REGEX;
			break;
		case 'E':
			G.cflags |= JSTR_RE_CF_EXTENDED;
			G.mode |= MODE_USE_REGEX;
			break;
		case 'I':
			G.cflags |= JSTR_RE_CF_ICASE;
			G.mode |= MODE_USE_REGEX;
			break;
		case 'Z':
			G.cflags |= JSTR_RE_CF_NEWLINE;
			break;
		case 'z':
			G.cflags &= ~JSTR_RE_CF_NEWLINE;
			break;
		default:
			break;
		}
	}
}

static unsigned short
get_terminal_rows(void)
{
	struct winsize w;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_row > 0) {
		return w.ws_row;
	}
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_row > 0) {
		return w.ws_row;
	}
	if (ioctl(STDERR_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_row > 0) {
		return w.ws_row;
	}
	const char *lines_env = getenv("LINES");
	if (lines_env != NULL) {
		int l = atoi(lines_env);
		if (l > 0) {
			return (unsigned short)l;
		}
	}
	return 24; /* standard default fallback */
}

jstr_ret_ty
confirm_interactive_loop(jstr_twoway_ty *R t,
                         jstr_ty *R find_buf,
                         jstr_ty *R rplc_buf,
                         jstr_ty *R flags_buf,
                         jstr_ty *R files_buf)
{
	setup_terminal();
	char err_buf[256];
	char last_err_buf[256];
	int needs_redraw = 1;
	int needs_recompile = 1;
	int is_valid = 1;
	int first_draw = 1;
	field_ty active_field = FIELD_FIND;
	size_t cursors[FIELD_COUNT];

	cursors[FIELD_FIND] = find_buf->size;
	cursors[FIELD_RPLC] = rplc_buf->size;
	cursors[FIELD_FLAGS] = flags_buf->size;
	cursors[FIELD_FILES] = files_buf->size;

	last_err_buf[0] = '\0';

	while (1) {
		if (needs_redraw) {
			if (first_draw) {
				jstr_io_fwrite("\x1b[2J\x1b[H", 1, 7, stdout);
				first_draw = 0;
			} else {
				/* Home cursor (move to top-left) */
				jstr_io_fwrite("\x1b[H", 1, 3, stdout);
			}

			if (needs_recompile) {
				/* Parse interactive flags from flags_buf */
				parse_interactive_flags(flags_buf->data ? flags_buf->data : "", flags_buf->size);

				err_buf[0] = '\0';
				jstr_ret_ty comp_ret = JSTR_RET_SUCC;
				const char *ptn = (find_buf->size > 0 && find_buf->data) ? find_buf->data : "";
				comp_ret = interactive_compile(t, ptn, find_buf->size, rplc_buf->data ? rplc_buf->data : "", rplc_buf->size, err_buf, sizeof(err_buf));
				is_valid = (comp_ret == JSTR_RET_SUCC);

				if (comp_ret != JSTR_RET_SUCC) {
					jstr_strcpy_len(last_err_buf, err_buf, strlen(err_buf));
				} else {
					last_err_buf[0] = '\0';
				}
				needs_recompile = 0;
			}

			size_t total_matches = 0;
			size_t files_matched = 0;
			size_t preview_lines = 0;

			if (!is_valid) {
				/* Clear entire screen once on compile error to wipe out previous previews/ghost lines */
				jstr_io_fwrite("\x1b[2J\x1b[H", 1, 7, stdout);
				/* Print regex compilation error in red */
				jstr_io_fwrite(COLOR_RED, 1, S_LEN(COLOR_RED), stdout);
				jstr_io_fwrite("Regex error: ", 1, 13, stdout);
				jstr_io_fwrite(last_err_buf, 1, strlen(last_err_buf), stdout);
				jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
				jstr_io_fwrite("\x1b[K\n", 1, 4, stdout);
				preview_lines = 1;
			} else {
				/* Calculate max_preview_lines dynamically based on terminal height */
				unsigned short rows = get_terminal_rows();
				if (rows > 9) {
					G.max_preview_lines = rows - 9;
				} else {
					G.max_preview_lines = 1;
				}

				/* If compile succeeded, run previews on all cached files */
				G.matches_found = 0;
				G.preview_lines_printed = 0;
				for (unsigned int k = 0; k < G.files.size; ++k) {
					file_ty *file = &G.files.data[k];
					/* File filtering by files_buf using jstr_strstr_len */
					if (files_buf->size > 0 && files_buf->data) {
						if (jstr_strstr_len(file->fname, file->fname_len, files_buf->data, files_buf->size) == NULL)
							continue;
					}
					size_t file_matches = 0;
					const char *ptn = (find_buf->size > 0 && find_buf->data) ? find_buf->data : "";
					confirm_scan_file(t, &file->content, file->fname, file->fname_len, ptn, find_buf->size, rplc_buf->data ? rplc_buf->data : "", rplc_buf->size, &file_matches);
					if (file_matches > 0) {
						total_matches += file_matches;
						files_matched++;
					}
				}
				if (G.preview_lines_printed >= G.max_preview_lines) {
					jstr_io_fwrite("... (some previews omitted)\x1b[K\n", 1, S_LEN("... (some previews omitted)\x1b[K\n"), stdout);
				}
				if (total_matches == 0) {
					/* Clear entire screen once on zero matches to wipe out previous previews/ghost lines */
					jstr_io_fwrite("\x1b[2J\x1b[H", 1, 7, stdout);
				}
				preview_lines = G.preview_lines_printed;
			}

			/* Render control fields at the bottom */
			if (!is_valid || total_matches == 0) {
				jstr_io_fwrite("--- Controls ---\x1b[K\n", 1, S_LEN("--- Controls ---\x1b[K\n"), stdout);
			} else {
				jstr_io_fwrite("\n--- Controls ---\x1b[K\n", 1, S_LEN("\n--- Controls ---\x1b[K\n"), stdout);
			}

			/* Statistics line */
			jstr_io_fwrite("  Stats:    ", 1, S_LEN("  Stats:    "), stdout);
			print_size_t(total_matches);
			jstr_io_fwrite(" matches, ", 1, S_LEN(" matches, "), stdout);
			print_size_t(files_matched);
			jstr_io_fwrite(" files\x1b[K\n", 1, S_LEN(" files\x1b[K\n"), stdout);

			jstr_io_fwrite(active_field == FIELD_FIND ? "* Find:    " : "  Find:    ", 1, 11, stdout);
			if (find_buf->size > 0 && find_buf->data)
				jstr_io_fwrite(find_buf->data, 1, find_buf->size, stdout);
			jstr_io_fwrite("\x1b[K\n", 1, 4, stdout);

			jstr_io_fwrite(active_field == FIELD_RPLC ? "* Replace: " : "  Replace: ", 1, 11, stdout);
			if (rplc_buf->size > 0 && rplc_buf->data)
				jstr_io_fwrite(rplc_buf->data, 1, rplc_buf->size, stdout);
			jstr_io_fwrite("\x1b[K\n", 1, 4, stdout);

			jstr_io_fwrite(active_field == FIELD_FLAGS ? "* Flags:   " : "  Flags:   ", 1, 11, stdout);
			if (flags_buf->size > 0 && flags_buf->data)
				jstr_io_fwrite(flags_buf->data, 1, flags_buf->size, stdout);
			jstr_io_fwrite("\x1b[K\n", 1, 4, stdout);

			jstr_io_fwrite(active_field == FIELD_FILES ? "* Files:   " : "  Files:   ", 1, 11, stdout);
			if (files_buf->size > 0 && files_buf->data)
				jstr_io_fwrite(files_buf->data, 1, files_buf->size, stdout);
			jstr_io_fwrite("\x1b[K\n", 1, 4, stdout);

			/* Clear from the current cursor position to the bottom of the screen */
			jstr_io_fwrite("\x1b[J", 1, 3, stdout);

			/* Compute absolute cursor position */
			size_t start_control_line = preview_lines + 1; /* Controls header */
			if (is_valid && total_matches > 0) {
				if (preview_lines >= G.max_preview_lines) {
					start_control_line += 1; /* omitted line */
				}
				start_control_line += 1; /* empty line before controls */
			}
			size_t find_line = start_control_line + 2;
			size_t active_line = find_line + (size_t)active_field;
			size_t active_col = 11 + cursors[active_field] + 1;

			char cup_buf[32];
			size_t cup_len = snprintf(cup_buf, sizeof(cup_buf), "\x1b[%zu;%zuH", active_line, active_col);
			jstr_io_fwrite(cup_buf, 1, cup_len, stdout);

			/* Show cursor */
			jstr_io_fwrite("\x1b[?25h", 1, 6, stdout);

			jstr_io_fflush(stdout);
			needs_redraw = 0;
		}

		char c;
		ssize_t nread = read(STDIN_FILENO, &c, 1);
		if (nread <= 0)
			continue;

		jstr_ty *active_buf = NULL;
		if (active_field == FIELD_FIND)
			active_buf = find_buf;
		else if (active_field == FIELD_RPLC)
			active_buf = rplc_buf;
		else if (active_field == FIELD_FLAGS)
			active_buf = flags_buf;
		else if (active_field == FIELD_FILES)
			active_buf = files_buf;

		if (c == '\r') {
			/* Accept only if the current pattern compiles successfully */
			if (is_valid)
				break;
		} else if (c == 10) {
			/* Ctrl-J or Arrow Down equivalent */
			active_field = (active_field + 1) % FIELD_COUNT;
			needs_redraw = 1;
		} else if (c == 11) {
			/* Ctrl-K or Arrow Up equivalent */
			active_field = (active_field + FIELD_COUNT - 1) % FIELD_COUNT;
			needs_redraw = 1;
		} else if (c == 27) {
			/* Check if this is Shift-Tab or Arrow keys escape sequence */
			struct termios raw;
			tcgetattr(STDIN_FILENO, &raw);
			raw.c_cc[VMIN] = 0;
			raw.c_cc[VTIME] = 1; /* 100ms timeout */
			tcsetattr(STDIN_FILENO, TCSANOW, &raw);

			char seq[2];
			int n1 = read(STDIN_FILENO, &seq[0], 1);
			int n2 = 0;
			if (n1 > 0)
				n2 = read(STDIN_FILENO, &seq[1], 1);

			/* Restore blocking read */
			raw.c_cc[VMIN] = 1;
			raw.c_cc[VTIME] = 0;
			tcsetattr(STDIN_FILENO, TCSANOW, &raw);

			if (n1 > 0 && n2 > 0) {
				if (seq[0] == '[' && seq[1] == 'Z') {
					/* Shift-Tab */
					active_field = (active_field + FIELD_COUNT - 1) % FIELD_COUNT;
					needs_redraw = 1;
				} else if (seq[0] == '[' && seq[1] == 'A') {
					/* Arrow Up */
					active_field = (active_field + FIELD_COUNT - 1) % FIELD_COUNT;
					needs_redraw = 1;
				} else if (seq[0] == '[' && seq[1] == 'B') {
					/* Arrow Down */
					active_field = (active_field + 1) % FIELD_COUNT;
					needs_redraw = 1;
				} else if (seq[0] == '[' && seq[1] == 'D') {
					/* Arrow Left: move active cursor left */
					if (cursors[active_field] > 0) {
						cursors[active_field]--;
						needs_redraw = 1;
					}
				} else if (seq[0] == '[' && seq[1] == 'C') {
					/* Arrow Right: move active cursor right */
					if (active_buf && cursors[active_field] < active_buf->size) {
						cursors[active_field]++;
						needs_redraw = 1;
					}
				} else if (seq[0] == '[' && seq[1] == '3') {
					char next_char;
					if (read(STDIN_FILENO, &next_char, 1) > 0 && next_char == '~') {
						/* Delete character at cursor */
						if (active_buf && cursors[active_field] < active_buf->size) {
							memmove(active_buf->data + cursors[active_field], active_buf->data + cursors[active_field] + 1, active_buf->size - cursors[active_field] - 1);
							active_buf->size--;
							active_buf->data[active_buf->size] = '\0';
							needs_redraw = 1;
							if (active_buf == find_buf || active_buf == flags_buf)
								needs_recompile = 1;
						}
					}
				}
			} else if (n1 <= 0) {
				/* Pure Escape: abort */
				restore_terminal();
				jstr_io_fwrite(CONFIRM_ABORTED, 1, S_LEN(CONFIRM_ABORTED), stderr);
				exit(EXIT_FAILURE);
			}
		} else if (c == 3 || c == 4) {
			/* Ctrl-C or Ctrl-D to abort */
			restore_terminal();
			jstr_io_fwrite(CONFIRM_ABORTED, 1, S_LEN(CONFIRM_ABORTED), stderr);
			exit(EXIT_FAILURE);
		} else if (c == 9) {
			/* Tab */
			active_field = (active_field + 1) % FIELD_COUNT;
			needs_redraw = 1;
		} else if (c == 127 || c == 8) {
			/* Backspace */
			if (active_buf && cursors[active_field] > 0) {
				/* Shift chars to the left of the cursor */
				memmove(active_buf->data + cursors[active_field] - 1, active_buf->data + cursors[active_field], active_buf->size - cursors[active_field]);
				active_buf->size--;
				active_buf->data[active_buf->size] = '\0';
				cursors[active_field]--;
				needs_redraw = 1;
				if (active_buf == find_buf || active_buf == flags_buf)
					needs_recompile = 1;
			}
		} else if (c == 21) {
			/* Ctrl-U */
			if (active_buf) {
				jstr_empty_j(active_buf);
				cursors[active_field] = 0;
				needs_redraw = 1;
				if (active_buf == find_buf || active_buf == flags_buf)
					needs_recompile = 1;
			}
		} else if ((unsigned char)c >= 32 && (unsigned char)c <= 126) {
			/* Printable character */
			if (active_buf) {
				/* Reserve space for 1 more char + NUL */
				DIE_IF(jstr_reserve_j(active_buf, active_buf->size + 2), "%s", "Out of memory.\n");
				/* Shift chars to the right of the cursor */
				memmove(active_buf->data + cursors[active_field] + 1, active_buf->data + cursors[active_field], active_buf->size - cursors[active_field]);
				/* Insert char at cursor */
				active_buf->data[cursors[active_field]] = c;
				active_buf->size++;
				active_buf->data[active_buf->size] = '\0';
				cursors[active_field]++;
				needs_redraw = 1;
				if (active_buf == find_buf || active_buf == flags_buf)
					needs_recompile = 1;
			}
		}
	}

	restore_terminal();
	return JSTR_RET_SUCC;
}
