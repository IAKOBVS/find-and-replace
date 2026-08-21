/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "confirm.h"
#include "files.h"
#include "process.h"
#include "vim.h"
#include <termios.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#ifdef __linux__
#include "procfs.h"
#endif

static struct termios orig_termios;
static int term_initialized = 0;
static const char *env_cols;
static const char *env_lines;

/* Terminal size fallbacks for when ioctl(TIOCGWINSZ) and the LINES/COLUMNS
 * environment variables are all unavailable (non-tty, redirected output). */
#define TERM_ROWS_FALLBACK 24
#define TERM_COLS_FALLBACK 80
/* Preview match budget multiplier: the -c scan collects at most
 * max_preview_lines * this many matches per file, so a -g global scan on a
 * huge tree cannot balloon into millions of collected matches on every TUI
 * redraw. The preview display only needs max_preview_lines lines anyway.
 * 4x covers same-line grouping (many matches merging into one block). */
#define PREVIEW_MATCH_BUDGET_FACTOR 4
/* Free-RAM estimate fallback when /proc/meminfo cannot be read; large enough
 * that the scan cache limit never artificially caps a preview. */
#define FREE_RAM_FALLBACK (1 * JSTR_IO_GIB)
/* Read buffer size for /proc/meminfo (a few KiB is far beyond the file size). */
#define MEMINFO_BUF_SIZE (4096 + 1)

static void
restore_terminal(void)
{
	if (term_initialized) {
		tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
		/* Use async-signal-safe write for signal safety when leaving alt screen and showing cursor */
		if (jstr_unlikely(write(STDOUT_FILENO, ANSI_ALT_SCREEN_DISABLE ANSI_CURSOR_SHOW, S_LEN(ANSI_ALT_SCREEN_DISABLE ANSI_CURSOR_SHOW)) < 0)) {}
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

static int
io_ok(void)
{
	return !ferror(stdout);
}

static void
term_clear_screen(void)
{
	if (jstr_unlikely(!io_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_CLEAR_SCREEN, 1, S_LEN(ANSI_CLEAR_SCREEN), stdout);
}

static void
term_home(void)
{
	if (jstr_unlikely(!io_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_HOME, 1, S_LEN(ANSI_HOME), stdout);
}

static void
term_clear_and_home(void)
{
	term_clear_screen();
	term_home();
}

static void
term_clear_line_end(void)
{
	if (jstr_unlikely(!io_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_CLEAR_LINE_END, 1, S_LEN(ANSI_CLEAR_LINE_END), stdout);
}

static void
term_clear_down(void)
{
	if (jstr_unlikely(!io_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_CLEAR_DOWN, 1, S_LEN(ANSI_CLEAR_DOWN), stdout);
}

static void
term_show_cursor(void)
{
	if (jstr_unlikely(!io_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_CURSOR_SHOW, 1, S_LEN(ANSI_CURSOR_SHOW), stdout);
}

static void
term_hide_cursor(void)
{
	if (jstr_unlikely(!io_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_CURSOR_HIDE, 1, S_LEN(ANSI_CURSOR_HIDE), stdout);
}

static void
term_move_cursor(size_t line, size_t col)
{
	if (jstr_unlikely(!io_ok()))
		return;
	(void)jstr_io_fwrite("\x1b[", 1, S_LEN("\x1b["), stdout);
	print_size_t(line);
	(void)jstr_io_putchar(';');
	print_size_t(col);
	(void)jstr_io_putchar('H');
}

static void
setup_terminal(void)
{
	if (jstr_unlikely(!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)))
		return;
	if (jstr_unlikely(tcgetattr(STDIN_FILENO, &orig_termios) < 0))
		return;
	struct termios raw = orig_termios;
	/* Raw mode: drop echo, line buffering, ^C/^Z/^V signals and flow control
	 * (so Ctrl-C reaches the editor, not the shell), and newline translation
	 * (so the editor sees '\n' as-is). Read returns after a single byte. */
	raw.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
	raw.c_iflag &= ~(IXON | ICRNL);
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;
	if (jstr_unlikely(tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0))
		return;
	term_initialized = 1;
	/* Enter alt screen, clear/home, hide cursor */
	if (jstr_unlikely(jstr_io_fwrite(ANSI_ALT_SCREEN_ENABLE, 1, S_LEN(ANSI_ALT_SCREEN_ENABLE), stdout) != S_LEN(ANSI_ALT_SCREEN_ENABLE))) {
		term_initialized = 0;
		return;
	}
	term_clear_and_home();
	term_hide_cursor();
	if (jstr_unlikely(jstr_io_fflush(stdout) == EOF)) {
		restore_terminal();
		return;
	}
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

static unsigned short
get_terminal_cols(void)
{
	struct winsize w;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0)
		return w.ws_col;
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0)
		return w.ws_col;
	if (ioctl(STDERR_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0)
		return w.ws_col;
	if (env_cols == NULL)
		env_cols = getenv("COLUMNS");
	if (env_cols != NULL) {
		int c = jstr_atoi(env_cols);
		if (c > 0)
			return (unsigned short)c;
	}
	return TERM_COLS_FALLBACK; /* standard default fallback */
}

static unsigned short
get_size_t_width(size_t val)
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
print_size_t(size_t val)
{
	if (jstr_unlikely(!io_ok()))
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

/* Print the "FNAME:LINE:PREFIX" prefix of one -c preview line. */
static void
print_line_prefix(const char *R fname, size_t fname_len, size_t line, char prefix, int is_selected)
{
	if (jstr_unlikely(!io_ok()))
		return;
	if (is_selected)
		(void)jstr_io_fwrite("\x1b[7m", 1, 4, stdout);
	(void)jstr_io_fwrite(fname, 1, fname_len, stdout);
	if (is_selected)
		(void)jstr_io_fwrite("\x1b[27m", 1, 5, stdout);
	(void)jstr_io_putchar(':');
	print_size_t(line);
	(void)jstr_io_putchar(':');
	(void)jstr_io_putchar(prefix);
}

/* Print S of LEN bytes, expanding tab characters to 8-column stops and
 * truncating/clipping to COLS - 1 columns. COL_PTR tracks the current column
 * (0-indexed). */
static void
print_diff_line_chars(const char *s, size_t len, unsigned short cols, unsigned short *col_ptr)
{
	if (jstr_unlikely(!io_ok()))
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
	if (jstr_unlikely(!io_ok()))
		return;
	const char *p = data;
	const char *const end = data + len;
	size_t line = start_line;
	const char *nl;
	unsigned short cols = 0;
	const size_t vis_end = G.scroll_offset + G.max_preview_lines;
	const int has_scroll = term_initialized && (G.scroll_offset > 0 || G.total_lines > G.max_preview_lines);
	if (term_initialized)
		cols = get_terminal_cols();
	int render = 1;
	(void)jstr_io_fwrite(color, 1, color_len, stdout);
	while ((nl = (const char *)memchr(p, '\n', (size_t)(end - p))) != NULL) {
		if (render && term_initialized && G.max_preview_lines > 0 && G.preview_lines_printed >= vis_end) {
			(void)jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
			render = 0;
		}
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
		print_line_prefix(fname, fname_len, line++, prefix, G.preview_lines_printed == G.selected_line);
		if (term_initialized) {
			unsigned short col = (unsigned short)(fname_len + get_size_t_width(line - 1) + 3);
			print_diff_line_chars(p, (size_t)(nl - p), cols, &col);
		} else {
			(void)jstr_io_fwrite(p, 1, (size_t)(nl - p), stdout);
		}
		if (term_initialized)
			(void)jstr_io_fwrite("\x1b[K", 1, S_LEN("\x1b[K"), stdout);
		(void)jstr_io_putchar('\n');
		if (term_initialized)
			G.preview_lines_printed++;
		p = nl + 1;
	}
	if (p < end) {
		if (render && term_initialized && G.max_preview_lines > 0 && G.preview_lines_printed >= vis_end) {
			(void)jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
			render = 0;
		}
		if (!render) {
			G.preview_lines_printed++;
		} else if (has_scroll && G.preview_lines_printed < G.scroll_offset) {
			G.preview_lines_printed++;
		} else {
			if (0)
				(void)jstr_io_fwrite("\x1b[7m", 1, 4, stdout);
			print_line_prefix(fname, fname_len, line, prefix, G.preview_lines_printed == G.selected_line);
			if (term_initialized) {
				unsigned short col = (unsigned short)(fname_len + get_size_t_width(line) + 3);
				print_diff_line_chars(p, (size_t)(end - p), cols, &col);
			} else {
				(void)jstr_io_fwrite(p, 1, (size_t)(end - p), stdout);
			}
			if (0)
				(void)jstr_io_fwrite("\x1b[27m", 1, 4, stdout);
			if (term_initialized)
				(void)jstr_io_fwrite("\x1b[K", 1, S_LEN("\x1b[K"), stdout);
			(void)jstr_io_putchar('\n');
			if (term_initialized)
				G.preview_lines_printed++;
		}
	} else if (trailing_nl) {
		if (render && term_initialized && G.max_preview_lines > 0 && G.preview_lines_printed >= vis_end) {
			(void)jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
			render = 0;
		}
		if (!render) {
			G.preview_lines_printed++;
		} else if (has_scroll && G.preview_lines_printed < G.scroll_offset) {
			G.preview_lines_printed++;
		} else {
			if (0)
				(void)jstr_io_fwrite("\x1b[7m", 1, 4, stdout);
			print_line_prefix(fname, fname_len, line, prefix, G.preview_lines_printed == G.selected_line);
			if (0)
				(void)jstr_io_fwrite("\x1b[27m", 1, 4, stdout);
			if (term_initialized)
				(void)jstr_io_fwrite("\x1b[K", 1, S_LEN("\x1b[K"), stdout);
			(void)jstr_io_putchar('\n');
			if (term_initialized)
				G.preview_lines_printed++;
		}
	}
	(void)jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
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
			/* Build the replacement content for this block into NEW_BUF. */
			jstr_empty_j(&G.new_buf);
			size_t p = block_start;
			for (size_t k = i; k <= j; ++k) {
				if (G.matches.data[k].start > p)
					DIE_IF(jstr_chk(jstr_append_len_j(&G.new_buf, buf->data + p, G.matches.data[k].start - p)), "%s", "Out of memory.\n");
				if (G.mode & MODE_USE_REGEX && backref) {
					size_t rplcwbackref_len = jstr_internal_re_rplcbackrefstrlen(G.matches.data[k].rm, rplc_backref1, rplc_backref1_e, rplc_len);
					jstr_empty_j(&G.rplc_buf);
					DIE_IF(jstr_chk(jstr_reserve_j(&G.rplc_buf, rplcwbackref_len + 1)), "%s", "Out of memory.\n");
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



/* Compile the interactive Include/Exclude fields into the global regexes.
 * An empty pattern clears the filter. On invalid regex, report it and return
 * JSTR_RET_ERR so the caller treats the whole session as invalid. */
static jstr_ret_ty
interactive_compile_include_exclude(const char *include, size_t include_len,
                                    const char *exclude, size_t exclude_len,
                                    char *err_buf, size_t err_size)
{
	if (include_len == 0) {
		if (G.have_include) {
			jstr_re_free(&G.include_re);
			G.have_include = 0;
		}
	} else {
		char tmp[128];
		const int ret = jstr_re_comp(&G.include_re, include, G.cflags);
		if (jstr_unlikely(ret != JSTR_RE_RET_NOERROR)) {
			regerror(ret, &G.include_re.reg, tmp, sizeof(tmp));
			snprintf(err_buf, err_size, "Invalid Include regex: %s", tmp);
			return JSTR_RET_ERR;
		}
		G.have_include = 1;
	}
	if (exclude_len == 0) {
		if (G.have_exclude) {
			jstr_re_free(&G.exclude_re);
			G.have_exclude = 0;
		}
	} else {
		char tmp[128];
		const int ret = jstr_re_comp(&G.exclude_re, exclude, G.cflags);
		if (jstr_unlikely(ret != JSTR_RE_RET_NOERROR)) {
			regerror(ret, &G.exclude_re.reg, tmp, sizeof(tmp));
			snprintf(err_buf, err_size, "Invalid Exclude regex: %s", tmp);
			return JSTR_RET_ERR;
		}
		G.have_exclude = 1;
	}
	return JSTR_RET_SUCC;
}

/* Return 1 if FILE passes the interactive filters: the Files substring
 * filter and the Include/Exclude basename regexes (in the global state). */
static int
interactive_file_pass(const file_ty *R file, const jstr_ty *R files_buf)
{
	if (files_buf->size > 0 && files_buf->data) {
		if (jstr_strstr_len(file->fname, file->fname_len, files_buf->data, files_buf->size) == NULL)
			return 0;
	}
	/* Include/Exclude regexes match against the basename. */
	const char *base = jstr_memrchr(file->fname, '/', file->fname_len);
	base = (base != NULL && *(base + 1)) ? base + 1 : file->fname;
	const size_t base_len = (size_t)(file->fname + file->fname_len - base);
	if (G.have_include)
		if (jstr_re_match_len(&G.include_re, base, base_len, 0) != JSTR_RE_RET_NOERROR)
			return 0;
	if (G.have_exclude)
		if (jstr_re_match_len(&G.exclude_re, base, base_len, 0) == JSTR_RE_RET_NOERROR)
			return 0;
	return 1;
}

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
		case 'l':
			G.mode |= MODE_PRINT_CHANGES;
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
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_row > 0)
		return w.ws_row;
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_row > 0)
		return w.ws_row;
	if (ioctl(STDERR_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_row > 0)
		return w.ws_row;
	if (env_lines == NULL)
		env_lines = getenv("LINES");
	if (env_lines != NULL) {
		int l = jstr_atoi(env_lines);
		if (l > 0)
			return (unsigned short)l;
	}
	return TERM_ROWS_FALLBACK; /* standard default fallback */
}

typedef struct {
	const field_ty field;
	const char *active_prefix;
	const size_t active_prefix_len;
	const char *inactive_prefix;
	const size_t inactive_prefix_len;
	const int affects_recompile;
} field_info_ty;

static const field_info_ty field_info_table[FIELD_COUNT] = {
	{ FIELD_FIND,    "* Find:    ", S_LEN("* Find:    "), "  Find:    ", S_LEN("  Find:    "), 1 },
	{ FIELD_RPLC,    "* Replace: ", S_LEN("* Replace: "), "  Replace: ", S_LEN("  Replace: "), 0 },
	{ FIELD_FLAGS,   "* Flags:   ", S_LEN("* Flags:   "), "  Flags:   ", S_LEN("  Flags:   "), 1 },
	{ FIELD_FILES,   "* Files:   ", S_LEN("* Files:   "), "  Files:   ", S_LEN("  Files:   "), 0 },
	{ FIELD_INCLUDE, "* Include: ", S_LEN("* Include: "), "  Include: ", S_LEN("  Include: "), 1 },
	{ FIELD_EXCLUDE, "* Exclude: ", S_LEN("* Exclude: "), "  Exclude: ", S_LEN("  Exclude: "), 1 },
	{ FIELD_BACKUP,  "* Backup:  ", S_LEN("* Backup:  "), "  Backup:  ", S_LEN("  Backup:  "), 0 }
};

/* Return the interactive buffer for a field, or NULL for out-of-range. */
static jstr_ty *
field_buf(jstr_ty *R find_buf, jstr_ty *R rplc_buf, jstr_ty *R flags_buf,
          jstr_ty *R files_buf, jstr_ty *R include_buf, jstr_ty *R exclude_buf,
          jstr_ty *R backup_buf, size_t field)
{
	switch (field) {
	case FIELD_FIND: return find_buf;
	case FIELD_RPLC: return rplc_buf;
	case FIELD_FLAGS: return flags_buf;
	case FIELD_FILES: return files_buf;
	case FIELD_INCLUDE: return include_buf;
	case FIELD_EXCLUDE: return exclude_buf;
	case FIELD_BACKUP: return backup_buf;
	default: return NULL;
	}
}

/* Fields whose edits require recompiling the find/include/exclude regexes. */
static int
field_affects_recompile(size_t field)
{
	if (field < FIELD_COUNT)
		return field_info_table[field].affects_recompile;
	return 0;
}

/* Copy SRC into DST with the FIND/REPLACE escape sequences unescaped, so the
 * live compile and preview see the same strings the CLI path would produce.
 * DST's size is set to the unescaped length. */
static void
jstr_unescape_copy(jstr_ty *R dst, const jstr_ty *R src)
{
	jstr_empty_j(dst);
	if (src->size > 0 && src->data) {
		DIE_IF(jstr_chk(jstr_assign_len_j(dst, src->data, src->size)), "%s", "Out of memory.\n");
		dst->size = JSTR_DIFF(jstr_unescape_p(dst->data), dst->data);
	}
}

static void
confirm_render_field(const field_info_ty *info, const jstr_ty *buf, int is_active)
{
	if (jstr_unlikely(!io_ok()))
		return;
	if (is_active)
		(void)jstr_io_fwrite(info->active_prefix, 1, info->active_prefix_len, stdout);
	else
		(void)jstr_io_fwrite(info->inactive_prefix, 1, info->inactive_prefix_len, stdout);
	if (buf && buf->size > 0 && buf->data)
		(void)jstr_io_fwrite(buf->data, 1, buf->size, stdout);
	term_clear_line_end();
}

static confirm_key_ty
confirm_read_key(char *out_char)
{
	char c;
	ssize_t nread = read(STDIN_FILENO, &c, 1);
	if (nread <= 0)
		return KEY_NONE;

	*out_char = c;

	if (c == '\r')
		return KEY_ENTER;
	if (c == 10)
		return KEY_CTRL_J;
	if (c == 11)
		return KEY_CTRL_K;
	if (c == 9)
		return KEY_TAB;
	if (c == 127 || c == 8)
		return KEY_BACKSPACE;
	if (c == 21)
		return KEY_CTRL_U;
	if (c == 3)
		return KEY_CTRL_C;
	if (c == 4)
		return KEY_CTRL_D;

	if (c == 27) {
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
			if (seq[0] == '[' && seq[1] == 'Z')
				return KEY_SHIFT_TAB;
			if (seq[0] == '[' && seq[1] == 'A')
				return KEY_UP;
			if (seq[0] == '[' && seq[1] == 'B')
				return KEY_DOWN;
			if (seq[0] == '[' && seq[1] == 'D')
				return KEY_LEFT;
			if (seq[0] == '[' && seq[1] == 'C')
				return KEY_RIGHT;
			if (seq[0] == '[' && seq[1] == '3') {
				char next_char;
				if (read(STDIN_FILENO, &next_char, 1) > 0 && next_char == '~')
					return KEY_DELETE;
			}
		} else if (n1 <= 0) {
			return KEY_ESC;
		}
		return KEY_NONE;
	}

	if ((unsigned char)c >= 32 && (unsigned char)c <= 126)
		return KEY_CHAR;

	return KEY_NONE;
}

static char err_buf[256];
static char last_err_buf[256];

static void
render_tui_header_and_stats(size_t start_control_line, size_t total_matches, size_t files_matched)
{
	term_move_cursor(start_control_line, 1);
	if (vim_is_insert_mode())
		(void)jstr_io_fwrite("-- [INSERT] --", 1, S_LEN("-- [INSERT] --"), stdout);
	else
		(void)jstr_io_fwrite("-- [NORMAL] --", 1, S_LEN("-- [NORMAL] --"), stdout);
	term_clear_line_end();
	(void)jstr_io_putchar('\n');

	/* Statistics line */
	(void)jstr_io_fwrite("  Stats:    ", 1, S_LEN("  Stats:    "), stdout);
	print_size_t(total_matches);
	if (G.preview_full)
		(void)jstr_io_putchar('+');
	(void)jstr_io_fwrite(" matches, ", 1, S_LEN(" matches, "), stdout);
	print_size_t(files_matched);
	if (G.preview_full)
		(void)jstr_io_putchar('+');
	(void)jstr_io_fwrite(" files", 1, S_LEN(" files"), stdout);
	term_clear_line_end();
	(void)jstr_io_putchar('\n');
}

/* Grep TUI field enum. */
enum {
	GREP_FIELD_FIND,
	GREP_FIELD_FILES,
	GREP_FIELD_INCLUDE,
	GREP_FIELD_EXCLUDE,
	GREP_FIELD_COUNT
};

typedef struct {
	const char *active_prefix;
	size_t active_prefix_len;
	const char *inactive_prefix;
	size_t inactive_prefix_len;
	int affects_recompile;
} grep_field_info_ty;

static const grep_field_info_ty grep_field_info_table[GREP_FIELD_COUNT] = {
	{ "* Find:    ", S_LEN("* Find:    "), "  Find:    ", S_LEN("  Find:    "), 1 },
	{ "* Files:   ", S_LEN("* Files:   "), "  Files:   ", S_LEN("  Files:   "), 0 },
	{ "* Include: ", S_LEN("* Include: "), "  Include: ", S_LEN("  Include: "), 1 },
	{ "* Exclude: ", S_LEN("* Exclude: "), "  Exclude: ", S_LEN("  Exclude: "), 1 },
};

static jstr_ty *
grep_field_buf(jstr_ty *R find_buf, jstr_ty *R files_buf, jstr_ty *R include_buf, jstr_ty *R exclude_buf, size_t field)
{
	switch (field) {
	case GREP_FIELD_FIND: return find_buf;
	case GREP_FIELD_FILES: return files_buf;
	case GREP_FIELD_INCLUDE: return include_buf;
	case GREP_FIELD_EXCLUDE: return exclude_buf;
	default: return NULL;
	}
}

static int
grep_field_affects_recompile(size_t field)
{
	if (field < GREP_FIELD_COUNT)
		return grep_field_info_table[field].affects_recompile;
	return 0;
}

/* Print one grep match line for the TUI: FNAME:LINE:CONTENT with the same
 * colored prefix as non-interactive grep. If IS_SELECTED, wrap in inverse
 * video. Returns 1 if the line was printed, 0 if budget exhausted. */
static int
grep_print_line(const grep_line_ty *gl, int is_selected, unsigned short cols)
{
	if (jstr_unlikely(!io_ok()))
		return 0;
	(void)jstr_io_fwrite(COLOR_RED, 1, S_LEN(COLOR_RED), stdout);
	if (is_selected)
		(void)jstr_io_fwrite("\x1b[7m", 1, 4, stdout);
	(void)jstr_io_fwrite(gl->fname, 1, gl->fname_len, stdout);
	if (is_selected)
		(void)jstr_io_fwrite("\x1b[27m", 1, 5, stdout);
	(void)jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
	(void)jstr_io_fputc(':', stdout);
	(void)jstr_io_fwrite(COLOR_GREEN, 1, S_LEN(COLOR_GREEN), stdout);
	print_size_t(gl->line_num);
	(void)jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
	(void)jstr_io_fputc(':', stdout);
	(void)jstr_io_fwrite(gl->content, 1, gl->match_off, stdout);
	(void)jstr_io_fwrite(COLOR_RED, 1, S_LEN(COLOR_RED), stdout);
	(void)jstr_io_fwrite(gl->content + gl->match_off, 1, gl->match_len, stdout);
	(void)jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
	const size_t after_off = gl->match_off + gl->match_len;
	const size_t after_len = gl->content_len - after_off;
	if (term_initialized) {
		unsigned short col = (unsigned short)(gl->fname_len + get_size_t_width(gl->line_num) + 3 + gl->match_off + gl->match_len);
		print_diff_line_chars(gl->content + after_off, after_len, cols, &col);
	} else {
		(void)jstr_io_fwrite(gl->content + after_off, 1, after_len, stdout);
	}
	if (term_initialized)
		(void)jstr_io_fwrite("\x1b[K", 1, S_LEN("\x1b[K"), stdout);
	(void)jstr_io_putchar('\n');
	return 1;
}

/* Re-scan all cached files and collect matching lines into G.grep_lines. */
static void
grep_rescan(jstr_twoway_ty *R t, const jstr_ty *R find_buf,
            jstr_ty *R files_buf, jstr_ty *R include_buf, jstr_ty *R exclude_buf)
{
	char ie_err[128];
	const char *inc = (include_buf && include_buf->size > 0 && include_buf->data) ? include_buf->data : "";
	const char *exc = (exclude_buf && exclude_buf->size > 0 && exclude_buf->data) ? exclude_buf->data : "";
	if (interactive_compile_include_exclude(inc, include_buf ? include_buf->size : 0, exc, exclude_buf ? exclude_buf->size : 0, ie_err, sizeof(ie_err)) != JSTR_RET_SUCC) {
		/* Invalid regex: skip filtering (show all files). */
		if (G.have_include) {
			jstr_re_free(&G.include_re);
			G.have_include = 0;
		}
		if (G.have_exclude) {
			jstr_re_free(&G.exclude_re);
			G.have_exclude = 0;
		}
	}
	G.grep_lines.size = 0;
	G.scroll_offset = 0;
	G.selected_line = 0;
	const char *ptn = (find_buf->size > 0 && find_buf->data) ? find_buf->data : "";
	const size_t find_len = find_buf->size;
	far_compile(t, ptn, find_len, "", 0, 1, NULL, 0);
	if (!(G.mode & MODE_USE_REGEX) || (G.mode & MODE_COMPILED)) {
		for (unsigned int k = 0; k < G.files.size; ++k) {
			file_ty *file = &G.files.data[k];
			if (!interactive_file_pass(file, files_buf))
				continue;
			grep_collect_file(t, &file->content, file->fname, file->fname_len, ptn, find_len);
		}
	}
	G.total_lines = G.grep_lines.size;
	if (G.selected_line >= G.total_lines && G.total_lines > 0)
		G.selected_line = G.total_lines - 1;
}

jstr_ret_ty
grep_interactive_loop(jstr_twoway_ty *R t,
                       jstr_ty *R find_buf,
                       jstr_ty *R files_buf,
                       jstr_ty *R include_buf,
                       jstr_ty *R exclude_buf)
{
	setup_terminal();
	if (jstr_unlikely(!term_initialized))
		return JSTR_RET_SUCC;
	vim_set_insert_mode(1);

	G.scroll_offset = 0;
	G.selected_line = 0;
	G.total_lines = 0;
	int needs_redraw = 1;
	int needs_rescan = 1;
	int first_draw = 1;
	size_t active_field = 0;
	size_t cursors[GREP_FIELD_COUNT];
	cursors[GREP_FIELD_FIND] = find_buf->size;
	cursors[GREP_FIELD_FILES] = files_buf->size;
	cursors[GREP_FIELD_INCLUDE] = include_buf->size;
	cursors[GREP_FIELD_EXCLUDE] = exclude_buf->size;

	for (;;) {
		if (needs_redraw) {
			if (jstr_unlikely(!io_ok()))
				break;
			if (first_draw) {
				term_clear_and_home();
				first_draw = 0;
			} else {
				term_home();
			}

			if (needs_rescan) {
				grep_rescan(t, find_buf, files_buf, include_buf, exclude_buf);
				needs_rescan = 0;
			}

			const unsigned short rows = get_terminal_rows();
			const size_t control_lines = GREP_FIELD_COUNT + 3;
			size_t max_preview_lines;
			if (rows > control_lines)
				max_preview_lines = rows - control_lines;
			else
				max_preview_lines = 1;
			G.max_preview_lines = max_preview_lines;

			/* Print matching lines in the scroll window. */
			unsigned short cols = 0;
			if (term_initialized)
				cols = get_terminal_cols();
			size_t printed = 0;
			const size_t vis_end = G.scroll_offset + max_preview_lines;
			for (size_t k = 0; k < G.grep_lines.size && printed < vis_end; ++k) {
				if (k < G.scroll_offset)
					continue;
				grep_print_line(&G.grep_lines.data[k], k == G.selected_line, cols);
				printed++;
			}
			if (G.grep_lines.size > vis_end) {
				(void)jstr_io_fwrite("... (more matches below)", 1, S_LEN("... (more matches below)"), stdout);
				term_clear_line_end();
				(void)jstr_io_putchar('\n');
			}

			term_clear_down();

			const size_t start_control_line = (rows > GREP_FIELD_COUNT + 1) ? rows - (GREP_FIELD_COUNT + 1) : 1;

			term_move_cursor(start_control_line, 1);

			if (vim_is_insert_mode())
				(void)jstr_io_fwrite("-- [INSERT] --", 1, S_LEN("-- [INSERT] --"), stdout);
			else
				(void)jstr_io_fwrite("-- [NORMAL] --", 1, S_LEN("-- [NORMAL] --"), stdout);
			term_clear_line_end();
			(void)jstr_io_putchar('\n');

			(void)jstr_io_fwrite("  Stats:    ", 1, S_LEN("  Stats:    "), stdout);
			print_size_t(G.grep_lines.size);
			(void)jstr_io_fwrite(" matches, ", 1, S_LEN(" matches, "), stdout);
			/* Count unique files. */
			size_t files_matched = 0;
			for (unsigned int k = 0; k < G.files.size; ++k) {
				int found = 0;
				for (size_t j = 0; j < G.grep_lines.size; ++j) {
					if (G.grep_lines.data[j].fname == G.files.data[k].fname) {
						found = 1;
						break;
					}
				}
				if (found)
					files_matched++;
			}
			print_size_t(files_matched);
			(void)jstr_io_fwrite(" files", 1, S_LEN(" files"), stdout);
			term_clear_line_end();
			(void)jstr_io_putchar('\n');

			for (size_t f = 0; f < GREP_FIELD_COUNT; ++f) {
				const jstr_ty *buf = grep_field_buf(find_buf, files_buf, include_buf, exclude_buf, f);
				const grep_field_info_ty *info = &grep_field_info_table[f];
				if (f == active_field)
					(void)jstr_io_fwrite(info->active_prefix, 1, info->active_prefix_len, stdout);
				else
					(void)jstr_io_fwrite(info->inactive_prefix, 1, info->inactive_prefix_len, stdout);
				if (buf && buf->size > 0 && buf->data)
					(void)jstr_io_fwrite(buf->data, 1, buf->size, stdout);
				term_clear_line_end();
				if (f != GREP_FIELD_COUNT - 1)
					(void)jstr_io_putchar('\n');
			}

			term_clear_down();

			size_t active_line = start_control_line + 2 + active_field;
			const grep_field_info_ty *ainfo = &grep_field_info_table[active_field];
			size_t active_col = ainfo->inactive_prefix_len + cursors[active_field] + 1;

			term_move_cursor(active_line, active_col);
			term_show_cursor();

			(void)jstr_unlikely(jstr_io_fflush(stdout) == EOF);
			needs_redraw = 0;
		}

		char c;
		confirm_key_ty key = confirm_read_key(&c);
		if (key == KEY_NONE)
			continue;

		jstr_ty *active_buf = grep_field_buf(find_buf, files_buf, include_buf, exclude_buf, active_field);

		switch (key) {
		case KEY_ENTER:
			if (G.grep_lines.size > 0 && G.selected_line < G.grep_lines.size) {
				restore_terminal();
				const grep_line_ty *gl = &G.grep_lines.data[G.selected_line];
				(void)jstr_io_fwrite(COLOR_RED, 1, S_LEN(COLOR_RED), stdout);
				(void)jstr_io_fwrite(gl->fname, 1, gl->fname_len, stdout);
				(void)jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
				(void)jstr_io_fputc(':', stdout);
				(void)jstr_io_fwrite(COLOR_GREEN, 1, S_LEN(COLOR_GREEN), stdout);
				print_size_t(gl->line_num);
				(void)jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
				(void)jstr_io_fputc(':', stdout);
				(void)jstr_io_fwrite(gl->content, 1, gl->content_len, stdout);
				(void)jstr_io_fputc('\n', stdout);
				return JSTR_RET_SUCC;
			}
			break;

		case KEY_CTRL_J:
			if (G.total_lines > 0 && G.selected_line + 1 < G.total_lines) {
				G.selected_line++;
				if (G.selected_line >= G.scroll_offset + G.max_preview_lines)
					G.scroll_offset = G.selected_line - G.max_preview_lines + 1;
				needs_redraw = 1;
			}
			break;

		case KEY_DOWN:
		case KEY_TAB:
			active_field = (active_field + 1) % GREP_FIELD_COUNT;
			needs_redraw = 1;
			break;

		case KEY_CTRL_K:
			if (G.selected_line > 0) {
				G.selected_line--;
				if (G.selected_line < G.scroll_offset)
					G.scroll_offset = G.selected_line;
				needs_redraw = 1;
			}
			break;

		case KEY_UP:
		case KEY_SHIFT_TAB:
			active_field = (active_field + GREP_FIELD_COUNT - 1) % GREP_FIELD_COUNT;
			needs_redraw = 1;
			break;

		case KEY_LEFT:
			if (cursors[active_field] > 0) {
				cursors[active_field]--;
				needs_redraw = 1;
			}
			break;

		case KEY_RIGHT:
			if (active_buf && cursors[active_field] < active_buf->size) {
				cursors[active_field]++;
				needs_redraw = 1;
			}
			break;

		case KEY_DELETE:
			if (active_buf && cursors[active_field] < active_buf->size) {
				memmove(active_buf->data + cursors[active_field], active_buf->data + cursors[active_field] + 1, active_buf->size - cursors[active_field] - 1);
				active_buf->size--;
				active_buf->data[active_buf->size] = '\0';
				needs_redraw = 1;
				if (grep_field_affects_recompile(active_field))
					needs_rescan = 1;
			}
			break;

		case KEY_ESC:
			vim_set_insert_mode(0);
			if (active_buf && cursors[active_field] >= active_buf->size && active_buf->size > 0)
				cursors[active_field] = active_buf->size - 1;
			needs_redraw = 1;
			break;

		case KEY_CTRL_C:
		case KEY_CTRL_D:
			restore_terminal();
			(void)jstr_io_fwrite(CONFIRM_ABORTED, 1, S_LEN(CONFIRM_ABORTED), stderr);
			exit(EXIT_FAILURE);

		case KEY_BACKSPACE:
			if (active_buf && cursors[active_field] > 0) {
				memmove(active_buf->data + cursors[active_field] - 1, active_buf->data + cursors[active_field], active_buf->size - cursors[active_field]);
				active_buf->size--;
				active_buf->data[active_buf->size] = '\0';
				cursors[active_field]--;
				needs_redraw = 1;
				if (grep_field_affects_recompile(active_field))
					needs_rescan = 1;
			}
			break;

		case KEY_CTRL_U:
			if (active_buf) {
				jstr_empty_j(active_buf);
				cursors[active_field] = 0;
				needs_redraw = 1;
				if (grep_field_affects_recompile(active_field))
					needs_rescan = 1;
			}
			break;

		case KEY_CHAR:
			if (vim_is_insert_mode()) {
				if (active_buf) {
					DIE_IF(jstr_chk(jstr_reserve_j(active_buf, active_buf->size + 2)), "%s", "Out of memory.\n");
					memmove(active_buf->data + cursors[active_field] + 1, active_buf->data + cursors[active_field], active_buf->size - cursors[active_field]);
					active_buf->data[cursors[active_field]] = c;
					active_buf->size++;
					active_buf->data[active_buf->size] = '\0';
					cursors[active_field]++;
					needs_redraw = 1;
					if (grep_field_affects_recompile(active_field))
						needs_rescan = 1;
				}
			} else {
				vim_handle_key(c, active_buf, cursors, &active_field, &needs_redraw, &needs_rescan, GREP_FIELD_COUNT);
				jstr_ty *new_active_buf = grep_field_buf(find_buf, files_buf, include_buf, exclude_buf, active_field);
				if (!vim_is_insert_mode() && new_active_buf && new_active_buf->size > 0 && cursors[active_field] >= new_active_buf->size)
					cursors[active_field] = new_active_buf->size - 1;
			}
			break;

		default:
			break;
		}
	}

	restore_terminal();
	return JSTR_RET_SUCC;
}

jstr_ret_ty
confirm_interactive_loop(jstr_twoway_ty *R t,
                         jstr_ty *R find_buf,
                         jstr_ty *R rplc_buf,
                         jstr_ty *R flags_buf,
                         jstr_ty *R files_buf,
                         jstr_ty *R include_buf,
                         jstr_ty *R exclude_buf,
                         jstr_ty *R backup_buf)
{
	setup_terminal();
	vim_set_insert_mode(1);
	int needs_redraw = 1;
	int needs_recompile = 1;
	int is_valid = 1;
	int first_draw = 1;
	size_t active_field = FIELD_FIND;
	size_t cursors[FIELD_COUNT];

	cursors[FIELD_FIND] = find_buf->size;
	cursors[FIELD_RPLC] = rplc_buf->size;
	cursors[FIELD_FLAGS] = flags_buf->size;
	cursors[FIELD_FILES] = files_buf->size;
	cursors[FIELD_INCLUDE] = include_buf->size;
	cursors[FIELD_EXCLUDE] = exclude_buf->size;
	cursors[FIELD_BACKUP] = backup_buf->size;

	last_err_buf[0] = '\0';

	/* Unescaped copies of FIND/REPLACE for the live compile and preview so the
	 * interactive fields behave like the CLI args. */
	jstr_ty find_plain = JSTR_INIT;
	jstr_ty rplc_plain = JSTR_INIT;

	for (;;) {
		if (needs_redraw) {
			if (jstr_unlikely(!io_ok()))
				break;
			jstr_unescape_copy(&find_plain, find_buf);
			jstr_unescape_copy(&rplc_plain, rplc_buf);
			if (first_draw) {
				term_clear_and_home();
				first_draw = 0;
			} else {
				/* Home cursor (move to top-left) */
				term_home();
			}

			if (needs_recompile) {
				/* Parse interactive flags from flags_buf */
				parse_interactive_flags(flags_buf->data ? flags_buf->data : "", flags_buf->size);

				err_buf[0] = '\0';
				jstr_ret_ty comp_ret = JSTR_RET_SUCC;
				const char *ptn = (find_plain.size > 0 && find_plain.data) ? find_plain.data : "";
				comp_ret = far_compile(t, ptn, find_plain.size, rplc_plain.data ? rplc_plain.data : "", rplc_plain.size, 1, err_buf, sizeof(err_buf));
				if (comp_ret == JSTR_RET_SUCC)
					comp_ret = interactive_compile_include_exclude(include_buf->data ? include_buf->data : "", include_buf->size, exclude_buf->data ? exclude_buf->data : "", exclude_buf->size, err_buf, sizeof(err_buf));
				is_valid = (comp_ret == JSTR_RET_SUCC);

				if (comp_ret != JSTR_RET_SUCC)
					jstr_strcpy_len(last_err_buf, err_buf, strlen(err_buf));
				else
					last_err_buf[0] = '\0';
				needs_recompile = 0;
				G.scroll_offset = 0;
				G.selected_line = 0;
			}

			size_t total_matches = 0;
			size_t files_matched = 0;
			const unsigned short rows = get_terminal_rows();

			if (!is_valid) {
				/* Clear entire screen once on compile error to wipe out previous previews/ghost lines */
				term_clear_and_home();
				/* Print regex compilation error in red */
				(void)jstr_io_fwrite(COLOR_RED, 1, S_LEN(COLOR_RED), stdout);
				(void)jstr_io_fwrite("Regex error: ", 1, S_LEN("Regex error: "), stdout);
				(void)jstr_io_fwrite(last_err_buf, 1, strlen(last_err_buf), stdout);
				(void)jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
				term_clear_line_end();
				(void)jstr_io_putchar('\n');
			} else {
				/* Calculate max_preview_lines dynamically based on terminal
				 * height, leaving room for the controls block: header + stats
				 * + FIELD_COUNT fields + blank line + omitted-line marker. */
				const size_t control_lines = FIELD_COUNT + 4;
				if (rows > control_lines)
					G.max_preview_lines = rows - control_lines;
				else
					G.max_preview_lines = 1;

				/* If compile succeeded, run previews on all cached files */
				G.matches_found = 0;
				G.preview_lines_printed = 0;
				G.preview_full = 0;
				for (unsigned int k = 0; k < G.files.size; ++k) {
					file_ty *file = &G.files.data[k];
					/* File filtering by the Files substring filter and the
					 * Include/Exclude basename regexes */
					if (!interactive_file_pass(file, files_buf))
						continue;
					size_t file_matches = 0;
					const char *ptn = (find_plain.size > 0 && find_plain.data) ? find_plain.data : "";
					confirm_scan_file(t, &file->content, file->fname, file->fname_len, ptn, find_plain.size, rplc_plain.data ? rplc_plain.data : "", rplc_plain.size, &file_matches);
					if (file_matches > 0) {
						total_matches += file_matches;
						files_matched++;
					}
				/* The match budget ran out: further files would only feed a
				 * preview that is already full. Stop scanning so a -g global
				 * scan on a large tree stays cheap per keystroke. */
				if (G.preview_full)
					break;
				}
				G.total_lines = G.preview_lines_printed;
				if (G.selected_line >= G.total_lines && G.total_lines > 0)
					G.selected_line = G.total_lines - 1;
			if (G.preview_lines_printed >= G.max_preview_lines || G.preview_full) {
				(void)jstr_io_fwrite("... (some previews omitted)", 1, S_LEN("... (some previews omitted)"), stdout);
				term_clear_line_end();
				(void)jstr_io_putchar('\n');
				}
			}

			/* Clear remaining preview area below the printed previews before rendering controls */
			term_clear_down();

			/* Render the control fields pinned to the bottom of the screen so
			 * the last field always ends on the terminal's last row; the
			 * preview area sits above. */
			const size_t start_control_line = (rows > FIELD_COUNT + 1) ? rows - (FIELD_COUNT + 1) : 1;
			render_tui_header_and_stats(start_control_line, total_matches, files_matched);

			for (size_t f = 0; f < FIELD_COUNT; ++f) {
				const jstr_ty *buf = field_buf(find_buf, rplc_buf, flags_buf, files_buf, include_buf, exclude_buf, backup_buf, f);
				confirm_render_field(&field_info_table[f], buf, f == active_field);
				if (f != FIELD_COUNT - 1)
					(void)jstr_io_putchar('\n');
			}

			/* Clear from the current cursor position to the bottom of the screen */
			term_clear_down();

			/* The cursor sits on the active field, anchored at the bottom.
			 * Fields start two rows below the header (after stats). */
			size_t active_line = start_control_line + 2 + (size_t)active_field;
			size_t active_col = field_info_table[active_field].inactive_prefix_len + cursors[active_field] + 1;

			term_move_cursor(active_line, active_col);
			term_show_cursor();

			(void)jstr_unlikely(jstr_io_fflush(stdout) == EOF);
			needs_redraw = 0;
		}

		char c;
		confirm_key_ty key = confirm_read_key(&c);
		if (key == KEY_NONE)
			continue;

		jstr_ty *active_buf = field_buf(find_buf, rplc_buf, flags_buf, files_buf, include_buf, exclude_buf, backup_buf, active_field);

		switch (key) {
		case KEY_ENTER:
			if (is_valid)
				goto done;
			break;

		case KEY_CTRL_J:
			if (G.total_lines > 0 && G.selected_line + 1 < G.total_lines) {
				G.selected_line++;
				if (G.selected_line >= G.scroll_offset + G.max_preview_lines)
					G.scroll_offset = G.selected_line - G.max_preview_lines + 1;
				needs_redraw = 1;
			}
			break;

		case KEY_DOWN:
		case KEY_TAB:
			active_field = (active_field + 1) % FIELD_COUNT;
			needs_redraw = 1;
			break;

		case KEY_CTRL_K:
			if (G.selected_line > 0) {
				G.selected_line--;
				if (G.selected_line < G.scroll_offset)
					G.scroll_offset = G.selected_line;
				needs_redraw = 1;
			}
			break;

		case KEY_UP:
		case KEY_SHIFT_TAB:
			active_field = (active_field + FIELD_COUNT - 1) % FIELD_COUNT;
			needs_redraw = 1;
			break;

		case KEY_LEFT:
			if (cursors[active_field] > 0) {
				cursors[active_field]--;
				needs_redraw = 1;
			}
			break;

		case KEY_RIGHT:
			if (active_buf && cursors[active_field] < active_buf->size) {
				cursors[active_field]++;
				needs_redraw = 1;
			}
			break;

		case KEY_DELETE:
			if (active_buf && cursors[active_field] < active_buf->size) {
				memmove(active_buf->data + cursors[active_field], active_buf->data + cursors[active_field] + 1, active_buf->size - cursors[active_field] - 1);
				active_buf->size--;
				active_buf->data[active_buf->size] = '\0';
				needs_redraw = 1;
				if (field_affects_recompile(active_field))
					needs_recompile = 1;
			}
			break;

		case KEY_ESC:
			vim_set_insert_mode(0);
			if (active_buf && cursors[active_field] >= active_buf->size && active_buf->size > 0)
				cursors[active_field] = active_buf->size - 1;
			needs_redraw = 1;
			break;

		case KEY_CTRL_C:
		case KEY_CTRL_D:
			restore_terminal();
			(void)jstr_io_fwrite(CONFIRM_ABORTED, 1, S_LEN(CONFIRM_ABORTED), stderr);
			exit(EXIT_FAILURE);

		case KEY_BACKSPACE:
			if (active_buf && cursors[active_field] > 0) {
				memmove(active_buf->data + cursors[active_field] - 1, active_buf->data + cursors[active_field], active_buf->size - cursors[active_field]);
				active_buf->size--;
				active_buf->data[active_buf->size] = '\0';
				cursors[active_field]--;
				needs_redraw = 1;
				if (field_affects_recompile(active_field))
					needs_recompile = 1;
			}
			break;

		case KEY_CTRL_U:
			if (active_buf) {
				jstr_empty_j(active_buf);
				cursors[active_field] = 0;
				needs_redraw = 1;
				if (field_affects_recompile(active_field))
					needs_recompile = 1;
			}
			break;

		case KEY_CHAR:
			if (vim_is_insert_mode()) {
				if (active_buf) {
					DIE_IF(jstr_chk(jstr_reserve_j(active_buf, active_buf->size + 2)), "%s", "Out of memory.\n");
					memmove(active_buf->data + cursors[active_field] + 1, active_buf->data + cursors[active_field], active_buf->size - cursors[active_field]);
					active_buf->data[cursors[active_field]] = c;
					active_buf->size++;
					active_buf->data[active_buf->size] = '\0';
					cursors[active_field]++;
					needs_redraw = 1;
					if (field_affects_recompile(active_field))
						needs_recompile = 1;
				}
			} else {
				vim_handle_key(c, active_buf, cursors, &active_field, &needs_redraw, &needs_recompile, FIELD_COUNT);
				jstr_ty *new_active_buf = field_buf(find_buf, rplc_buf, flags_buf, files_buf, include_buf, exclude_buf, backup_buf, active_field);

				if (!vim_is_insert_mode() && new_active_buf && new_active_buf->size > 0 && cursors[active_field] >= new_active_buf->size)
					cursors[active_field] = new_active_buf->size - 1;
			}
			break;

		default:
			break;
		}
	}

done:
	restore_terminal();
#if DO_FREE /* Buffer reused across redraws; freeing is optional pre-exit. */
	jstr_free_j(&find_plain);
	jstr_free_j(&rplc_plain);
#endif
	return JSTR_RET_SUCC;
}
