/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#define JSTR_PANIC                 0
#define JSTR_USE_UNLOCKED_IO_READ  1
#define JSTR_USE_UNLOCKED_IO_WRITE 1

#include <jstr/jstr.h>
#include <jstr/io.h>
#include <jstr/regex.h>
#include <jstr/stdstring.h>

#define S_LEN(s)     (sizeof(s) - 1)
#define S_LITERAL(s) (s), (sizeof(s) - 1)

#include <fnmatch.h>

/* Die-with-message helpers and short argument aliases used in main(). */
#define DIE_IF_PRINT(x, fmt, ...)                      \
	do {                                           \
		if (jstr_unlikely(x))                  \
			jstr_errdie(fmt, __VA_ARGS__); \
	} while (0)
#define DIE_IF(x, fmt, ...) DIE_IF_PRINT(x, fmt, __VA_ARGS__)
#define DIE()               DIE_IF(1)
#define ARG                 argv[i]
#define ARG_NEXT()          ++i
#define ARG_PREV()          --i
#define IS_REG(x)           S_ISREG(x)
#define IS_DIR(x)           S_ISDIR(x)
#define FIND                argv[1]
#define RPLC                argv[2]
#define R                   JSTR_RESTRICT

#define _(x) x
#define SEP  '/'

/* ANSI escape codes used to highlight the -c confirm mode preview. */
#define COLOR_RED           "\x1b[31m"
#define COLOR_GREEN         "\x1b[32m"
#define COLOR_RESET         "\x1b[0m"
#define CONFIRM_PROMPT      "Confirm changes? [y/N]: "
#define CONFIRM_ABORTED     "Aborted.\n"
#define INITIAL_MATCHES_CAP 8

#define DO_FREE 0

/* Mode bits tracked in G.mode: where output goes and what FIND means. */
typedef enum {
	MODE_PRINT_STDOUT = 1 << 0,
	MODE_PRINT_FILE = 1 << 1,
	MODE_PRINT_FILE_BACKUP = 1 << 2,
	MODE_PRINT_CHANGES = 1 << 3,
	MODE_USE_RECURSIVE = 1 << 4,
	MODE_USE_REGEX = 1 << 5,
	MODE_COMPILED = 1 << 6,
	MODE_HAVE_FILES = 1 << 7,
	MODE_CONFIRM = 1 << 8,
} mode_ty;

/* One byte range of a find occurrence, relative to the start of the file. */
typedef struct match_ty {
	size_t start;
	size_t end;
} match_ty;

typedef struct matches_ty {
	size_t cap;
	size_t size;
	match_ty *data;
} matches_ty;

/* One file collected during the -c scan pass: its name, stat, and full
 * content. The content buffer is stolen from the shared buf so pass 2 edits
 * it from memory instead of re-walking argv/ftw or re-reading the file. */
typedef struct file_ty {
	char *fname;
	size_t fname_len;
	struct stat st;
	jstr_ty content;
} file_ty;

typedef struct files_ty {
	size_t cap;
	size_t size;
	file_ty *data;
} files_ty;

/* Process-wide settings gathered from the command line. */
typedef struct global_ty {
	const char *include_glob;
	const char *bak_suffix;
	size_t bak_suffix_len;
	size_t n;
	int mode;
	int cflags;
	int eflags;
	/* Set by the scan pass when at least one match exists; decides whether the
	 * confirmation prompt is shown. */
	unsigned int matches_found;
	/* 1 while in the -c dry-run pass: process_file only scans/reports matches
	 * instead of modifying files. Reset before the second (real) pass. */
	int confirm_pass;
	jstr_re_ty regex;
	matches_ty matches;
	/* Growable list of files to edit once the user confirms. */
	files_ty files;
} global_ty;
global_ty G = { .mode = MODE_PRINT_STDOUT };

/* stat() wrapper: returns JSTR_RET_ERR (instead of failing silently) on error. */
JSTR_FUNC
static jstr_ret_ty
xstat(const char *R file,
      struct stat *R buf)
{
	if (jstr_unlikely(stat(file, buf)))
		goto err;
	return JSTR_RET_SUCC;
err:
	JSTR_RETURN_ERR(JSTR_RET_ERR);
}

/* True if FNAME exists at all. Used only to detect backup-name collisions;
 * access() is called with F_OK alone so read-only files still count. */
static int
file_exists(const char *R fname)
{
	return access(fname, F_OK) == 0;
}

typedef enum {
	/* Unknown file type. */
	FT_UNKNOWN = 0,
#define FT_UNKNOWN FT_UNKNOWN
	/* Text file type. */
	FT_TEXT,
#define FT_TEXT FT_TEXT
	/* Binary file type. */
	FT_BINARY
#define FT_BINARY FT_BINARY
} ft_ty;

#if 0
static ft_ty
exttype(const char *fname, size_t fname_len)
{
	fname = jstr_memrchr(fname, '.', fname_len);
	if (fname != NULL && *++fname != '\0') {
		static const char *textv[] = { "C", "S", "c", "cc", "cs", "cpp", "h", "hh", "hpp", "html", "js", "json", "md", "pl", "pm", "py", "pyi", "rs", "s", "sh", "ts", "txt" };
		static const char *binv[] = { "a", "bin", "gz", "jpg", "jpeg", "mp4", "mp3", "mkv", "o", "pdf", "png", "pyc", "rar", "so", "wav", "zip" };
		unsigned int i;
		for (i = 0; i < sizeof(textv) / sizeof(*textv); ++i)
			if (!jstr_strcmpeq_loop(fname, textv[i]))
				return FT_TEXT;
		for (i = 0; i < sizeof(binv) / sizeof(*binv); ++i)
			if (!jstr_strcmpeq_loop(fname, binv[i]))
				return FT_BINARY;
	}
	return FT_UNKNOWN;
}
#endif

static jstr_ret_ty
process_buffer(const jstr_twoway_ty *R t,
               jstr_ty *R buf,
               const char *R fname,
               size_t fname_len,
               const struct stat *st,
               const char *R find,
               const size_t find_len,
               const char *R rplc,
               const size_t rplc_len)
{
	/* Holds the length of the replaced output. As a size_t when the fixed
	 * and regex paths both store a length; the regex variant returns a
	 * signed offset type that may hold a negative error code. */
	union u {
		size_t zu;
		jstr_re_off_ty d;
	} changed;
	int fd_tmp = -1;
	char *bakp = NULL;
	char bak[JSTR_IO_PATH_MAX];
	if (G.mode & MODE_USE_REGEX) {
		/* The regex engine rejects empty patterns, so short-circuit them. */
		if (jstr_unlikely(find_len == 0)) {
			changed.zu = 0;
		} else {
			changed.d = jstr_re_rplcn_backref_len_exec_j(&G.regex, buf, rplc, rplc_len, G.eflags, 10, G.n);
			if (jstr_re_chk(changed.d)) {
				jstr_re_errdie(changed.d, &G.regex, "%s", "Regex replacement failed.\n");
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			changed.zu = (size_t)changed.d;
		}
	} else {
		/* Fixed-string path uses the precompiled Two-Way matcher. */
		changed.zu = jstr_rplcn_len_exec_j(t, buf, find, find_len, rplc, rplc_len, G.n);
		if (jstr_unlikely(changed.zu == (size_t)-1))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	/* Append newline if has space */
	/* Keep the final buffer newline-terminated so file output ends cleanly. */
	if (buf->size && buf->data[buf->size - 1] != '\n' && buf->capacity >= buf->size + S_LEN("\n") + 1)
		buf->size = JSTR_PTR_DIFF(jstr_append_len_unsafe_p(buf->data, buf->size, "\n", 1), buf->data);
	if (G.mode & MODE_PRINT_STDOUT) {
		/* Default mode: write the (replaced) buffer to stdout. */
		if (jstr_unlikely(jstr_io_fwrite(buf->data, 1, buf->size, stdout) != buf->size))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	} else {
		/* In-place mode (-i): nothing to do if nothing changed. */
		if (changed.zu == 0)
			return JSTR_RET_SUCC;
		if (G.mode & MODE_PRINT_FILE_BACKUP) {
			/* -iSUFFIX: rename the original aside, then write the new file. */
			if (jstr_unlikely(fname_len + G.bak_suffix_len >= sizeof(bak))) {
				jstr_errdie("Suffix length is too large to create a backup file (%zu >= %zu).\n", fname_len + G.bak_suffix_len, sizeof(bak));
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			char *p = jstr_mempcpy(bak, fname, fname_len);
			jstr_strcpy_len(p, G.bak_suffix, G.bak_suffix_len);
			if (jstr_unlikely(file_exists(bak))) {
				jstr_errdie("Can't make a backup file because suffixed filename (%s) already exists.\n", bak);
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			if (jstr_unlikely(rename(fname, bak)))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			if (jstr_chk(jstr_io_writefile_len_j(buf, fname, O_CREAT | O_TRUNC | O_WRONLY, st->st_mode & (S_IRWXO | S_IRWXG | S_IRWXU))))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		} else {
			/* Plain -i: write to a temp file next to the original, then
			 * rename it over the original for an atomic replace. */
			bakp = bak;
			if (jstr_unlikely(fname_len + S_LEN(".XXXXXX") >= sizeof(bak))) {
				jstr_errdie("Filename (%s) is too large to create a backup file (%zu >= %zu).\n", fname, fname_len + S_LEN(".XXXXXX"), sizeof(bak));
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			char *p = jstr_mempcpy(bak, fname, fname_len);
			p = jstr_stpcpy_len(p, S_LITERAL(".XXXXXX"));
			fd_tmp = mkstemp(bak);
			if (jstr_unlikely(fd_tmp == -1)) {
				bakp = NULL;
				jstr_errdie("Can't make a file (%s) to temporarily write replacements to.\n", bak);
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			if (jstr_chk(jstr_io_writefilefd_len_j(buf, fd_tmp))) {
				jstr_errdie("Can't write replacements to temp file (%s).\n", bak);
				goto err;
			}
			if (jstr_unlikely(close(fd_tmp) == -1)) {
				fd_tmp = -1;
				jstr_errdie("Can't close temp file (%s).\n", bak);
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			fd_tmp = -1;
			if (jstr_unlikely(rename(bak, fname))) {
				jstr_errdie("Can't rename temp file (%s) to original file (%s).\n", bak, fname);
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			bakp = NULL;
		}
		/* The file was successfully rewritten in place: report its name on
		 * stderr (never stdout) so the caller can see what changed. */
		if (jstr_unlikely(jstr_io_fwrite(fname, 1, fname_len, stderr) != fname_len))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		if (jstr_unlikely(jstr_io_fputc('\n', stderr) == EOF))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		if (G.mode & MODE_PRINT_CHANGES) {
			if (jstr_unlikely(jstr_io_fwrite(fname, 1, fname_len, stdout) != fname_len))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			if (jstr_chk(jstr_io_putchar('\n')))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		}
	}
	return JSTR_RET_SUCC;
err:
	if (fd_tmp != -1)
		if (close(fd_tmp) < 0) {}
	if (bakp != NULL)
		if (unlink(bakp) < 0) {}
	return JSTR_RET_ERR;
}

/* Append one match range to the dynamically grown matches array. */
static void
match_add(match_ty * R * R matches,
          size_t *R cap,
          size_t *R cnt,
          size_t start,
          size_t end)
{
	if (*cnt >= *cap) {
		*cap = *cap == 0 ? INITIAL_MATCHES_CAP : *cap * 2;
		match_ty *const new_matches = (match_ty *)realloc(*matches, *cap * sizeof(match_ty));
		DIE_IF(!new_matches, "%s", "Out of memory allocating matches.\n");
		*matches = new_matches;
	}
	(*matches)[*cnt].start = start;
	(*matches)[*cnt].end = end;
	++*cnt;
}

/* Append one file to the -c confirm cache. The name is strdup'd because
 * ftw->dirpath is a transient buffer reused across callbacks; the content
 * buffer is stolen from the shared buf so pass 2 needs no disk I/O. */
static void
file_add(const char *R fname,
         size_t fname_len,
         const struct stat *st,
         jstr_ty *R buf)
{
	if (G.files.size >= G.files.cap) {
		G.files.cap = G.files.cap == 0 ? INITIAL_MATCHES_CAP : G.files.cap * 2;
		file_ty *const tmp = (file_ty *)realloc(G.files.data, G.files.cap * sizeof(file_ty));
		DIE_IF(!tmp, "%s", "Out of memory allocating cached files.\n");
		G.files.data = tmp;
	}
	G.files.data[G.files.size].fname = (char *)malloc(fname_len + 1);
	DIE_IF(!G.files.data[G.files.size].fname, "%s", "Out of memory copying cached filename.\n");
	jstr_strcpy_len(G.files.data[G.files.size].fname, fname, fname_len);
	G.files.data[G.files.size].fname_len = fname_len;
	G.files.data[G.files.size].st = *st;
	/* Take ownership of the already-read content and reset the shared buffer. */
	G.files.data[G.files.size].content = *buf;
	*buf = (jstr_ty)JSTR_INIT;
	++G.files.size;
}

/* Return the offset of the first byte of the line containing IDX. */
static size_t
line_get_start(const char *R data, size_t size, size_t idx)
{
	if (idx > size)
		idx = size;
	while (idx > 0 && data[idx - 1] != '\n')
		--idx;
	return idx;
}

/* Return one past the last byte of the line containing IDX (the index of the
 * terminating '\n', or SIZE if the line is not newline-terminated). */
static size_t
line_get_end(const char *R data, size_t size, size_t idx)
{
	while (idx < size && data[idx] != '\n')
		++idx;
	return idx;
}

/* Count the 1-based line number of byte offset IDX. */
static size_t
line_get_number(const char *R data, size_t size, size_t idx)
{
	size_t line = 1;
	size_t i;
	for (i = 0; i < idx && i < size; ++i)
		if (data[i] == '\n')
			++line;
	return line;
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

/* Write a byte range to stdout, emitting the "file:line:" prefix lazily: the
 * prefix is printed only when a line boundary is crossed, so that a single
 * highlighted span that wraps across lines still gets a prefix per line and
 * the prefix never lands inside a highlight block. */
static void
print_segment(const char *R data,
              size_t len,
              const char *R fname,
              size_t fname_len,
              size_t *R line,
              int *R at_line_start)
{
	size_t i;
	for (i = 0; i < len; ++i) {
		if (*at_line_start) {
			jstr_io_fwrite(COLOR_RED, 1, S_LEN(COLOR_RED), stdout);
			jstr_io_fwrite(fname, 1, fname_len, stdout);
			jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
			jstr_io_putchar(':');
			jstr_io_fwrite(COLOR_GREEN, 1, S_LEN(COLOR_GREEN), stdout);
			print_size_t(*line);
			jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
			jstr_io_putchar(':');
			*at_line_start = 0;
		}
		jstr_io_putchar(data[i]);
		if (data[i] == '\n') {
			++*line;
			*at_line_start = 1;
		}
	}
}

static jstr_ret_ty
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
	/* Collect every match range so they can be grouped by line for display. */
	G.matches.size = 0;
	if (G.mode & MODE_USE_REGEX) {
		if (find_len > 0) {
			size_t off = 0;
			regmatch_t rm = { 0 };
			/* Search from each offset onward, mirroring the replacement loop
			 * in process_buffer so the preview matches what will be changed. */
			while (off < buf->size) {
				int eflags = G.eflags;
				/* '^' must not match again mid-line unless a newline anchor
				 * is active and the previous byte was a newline. */
				if (off > 0 && !(G.cflags & JSTR_RE_CF_NEWLINE && buf->data[off - 1] == '\n'))
					eflags |= REG_NOTBOL;
				const int ret = jstr_re_exec_len(&G.regex, buf->data + off, buf->size - off, 1, &rm, eflags);
				if (ret == JSTR_RE_RET_NOMATCH)
					break;
				if (ret != JSTR_RE_RET_NOERROR)
					break;
				const size_t m_start = off + (size_t)rm.rm_so;
				const size_t m_end = off + (size_t)rm.rm_eo;
				match_add(&G.matches.data, &G.matches.cap, &G.matches.size, m_start, m_end);
				if (G.n == 1)
					break;
				off = m_end;
				/* Force progress on a zero-length match (e.g. '^$'). */
				if (rm.rm_so == rm.rm_eo)
					++off;
			}
		}
	} else {
		if (find_len > 0) {
			size_t off = 0;
			/* Fixed-string pass uses the precompiled Two-Way matcher. */
			while (off < buf->size) {
				const char *const p = (const char *)jstr_memmem_exec(t, buf->data + off, buf->size - off, find, find_len);
				if (p == NULL)
					break;
				const size_t m_start = (size_t)JSTR_PTR_DIFF(p, buf->data);
				const size_t m_end = m_start + find_len;
				match_add(&G.matches.data, &G.matches.cap, &G.matches.size, m_start, m_end);
				if (G.n == 1)
					break;
				off = m_end;
			}
		}
	}
	if (G.matches.size > 0) {
		G.matches_found = 1;
		/* Print one line per original source line: merge all matches that
		 * fall on the same line into a single block so the "file:line:"
		 * prefix is printed only once per line. */
		size_t i = 0;
		while (i < G.matches.size) {
			/* Group consecutive matches that lie on the same line into one block. */
			size_t j = i;
			while (j + 1 < G.matches.size && line_get_start(buf->data, buf->size, G.matches.data[j + 1].start) <= line_get_end(buf->data, buf->size, G.matches.data[j].end))
				++j;
			const size_t block_start = line_get_start(buf->data, buf->size, G.matches.data[i].start);
			const size_t block_end = line_get_end(buf->data, buf->size, G.matches.data[j].end);
			size_t line = line_get_number(buf->data, buf->size, G.matches.data[i].start);
			size_t p = block_start;
			int at_line_start = 1;
			size_t k;
			/* Between, in, and after each match of the block: untouched text
			 * is printed plain, matched text in red, replacement in green. */
			for (k = i; k <= j; ++k) {
				if (G.matches.data[k].start > p)
					print_segment(buf->data + p, G.matches.data[k].start - p, fname, fname_len, &line, &at_line_start);
				jstr_io_fwrite(COLOR_RED, 1, S_LEN(COLOR_RED), stdout);
				print_segment(buf->data + G.matches.data[k].start, G.matches.data[k].end - G.matches.data[k].start, fname, fname_len, &line, &at_line_start);
				jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
				jstr_io_fwrite(COLOR_GREEN, 1, S_LEN(COLOR_GREEN), stdout);
				print_segment(rplc, rplc_len, fname, fname_len, &line, &at_line_start);
				jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
				p = G.matches.data[k].end;
			}
			if (block_end > p)
				print_segment(buf->data + p, block_end - p, fname, fname_len, &line, &at_line_start);
			jstr_io_putchar('\n');
			i = j + 1;
		}
	}
	*out_matches = G.matches.size;
	return JSTR_RET_SUCC;
}

static jstr_ret_ty
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
	/* A fixed-string find longer than the whole file cannot match. */
	if (!(G.mode & MODE_USE_REGEX) && file_size < find_len)
		return JSTR_RET_SUCC;
	/* Preallocate the length of the replace string. */
	/* Worst-case output size = input + (longer replace) + trailing newline. */
	if (rplc_len > find_len && !(G.mode & MODE_USE_REGEX))
		if (jstr_chk(jstr_reserve_j(buf, file_size + rplc_len - find_len + S_LEN("\n") + 1)))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (jstr_chk(jstr_io_readfile_len_j(buf, fname, 0, file_size)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	/* Skip files with NUL bytes in the first 1 KiB. */
	if (jstr_io_isbinary(buf->data, JSTR_MIN(1024, file_size)))
		return JSTR_RET_SUCC;
	/* During the -c dry-run pass, only scan and preview; the real edit
	 * happens on the second pass after the user confirms. The file's content
	 * is recorded so pass 2 edits it from memory without re-reading disk. */
	if (G.confirm_pass && (G.mode & MODE_CONFIRM)) {
		size_t matches = 0;
		jstr_ret_ty ret = confirm_scan_file(t, buf, fname, fname_len, find, find_len, rplc, rplc_len, &matches);
		/* Only files with matches need editing on pass 2; steal their buffer. */
		if (matches > 0)
			file_add(fname, fname_len, st, buf);
		return ret;
	}
	jstr_ret_ty ret = process_buffer(t, buf, fname, fname_len, st, find, find_len, rplc, rplc_len);
	return ret;
}

/* Per-directory-traversal context passed through ftw to callback_file. */
typedef struct args_ty {
	jstr_ty *buf;
	const char *find;
	size_t find_len;
	const char *rplc;
	size_t rplc_len;
	const jstr_twoway_ty *t;
} args_ty;

/* ftw callback: process every regular file the traversal yields. */
static JSTR_IO_FTW_FUNC(callback_file, ftw, args)
{
	const args_ty *const a = args;
	if (jstr_chk(process_file(a->t, a->buf, ftw->dirpath, ftw->dirpath_len, ftw->st, a->find, a->find_len, a->rplc, a->rplc_len)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_SUCC;
}

/* Glob matcher state shared by --include/--exclude. */
typedef struct matcher_args_ty {
	const char *include_glob;
	const char *exclude_glob;
} matcher_args_ty;

/* ftw matcher: return 1 to skip a file. --include only admits files whose
 * basename matches; --exclude skips files whose basename matches. */
static JSTR_IO_FTW_FUNC_MATCH(matcher, fname, fname_len, args)
{
	matcher_args_ty *a = (matcher_args_ty *)args;
	if (a->include_glob)
		if (fnmatch(a->include_glob, fname, 0))
			return 1;
	if (a->exclude_glob)
		if (!fnmatch(a->exclude_glob, fname, 0))
			return 1;
	return 0;
	(void)fname_len;
}

/* Compile FIND once (regex or Two-Way fixed-string matcher) into the global
 * state; MODE_COMPILED prevents recompilation on the second -c pass. */
static jstr_ret_ty
compile(jstr_twoway_ty *R t, const char *R find, size_t find_len)
{
	if (!(G.mode & MODE_COMPILED)) {
		if (G.mode & MODE_USE_REGEX) {
			const int ret = jstr_re_comp(&G.regex, find, G.cflags);
			if (jstr_unlikely(ret != JSTR_RE_RET_NOERROR)) {
				jstr_re_err(ret, &G.regex, "regex compilation failed for pattern \"%s\".\n", find);
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
		} else {
			jstr_memmem_comp(t, find, find_len);
		}
		G.mode |= MODE_COMPILED;
	}
	return JSTR_RET_SUCC;
}

/* Default flags. */
void
init_defaults()
{
	/* Anchors match on newlines. */
	G.cflags |= JSTR_RE_CF_NEWLINE;
	/* Non-global replacement. */
	G.n = 1;
}

/* clang-format off */

const char *usage =
	_("Usage: find-and-replace [FIND] [REPLACE] [OPTIONS]... [FILES]...\n")
	_("Options:\n")
	_("  -G (default)\n")
	_("    Replace first occurence of FIND with REPLACE.\n")
	_("  -g\n")
	_("    Replace all occurrences of FIND with REPLACE, negates -G flag.\n")
	_("  -i[SUFFIX]\n")
	_("    Replace files in-place. The default is printing to stdout.\n")
	_("    If SUFFIX is provided, backup the original file suffixed with SUFFIX.\n")
	_("  -c\n")
	_("    Confirm mode. Dry-run scans the files and prints all matches in\n")
	_("    file:line:line_content format, with the text to remove in red and the\n")
	_("    replacement text in green. Prompts for confirmation ('y') before\n")
	_("    modifying files in-place. Requires -i and at least one file.\n")
	_("  -r\n")
	_("    Recurse on the directories in FILES.\n")
	_("  --include GLOB\n")
	_("    File glob to match when -r is used. Glob is a wildcard.\n")
	_("  --exclude GLOB\n")
	_("    The reverse of --include. Skip files that match glob.\n")
	_("    This applies to the passed command line files.\n")
	_("  -F (default)\n")
	_("    Treat FIND as a fixed-string.\n")
	_("  -R\n")
	_("    Treat FIND as a regex, negates -F flag.\n")
	_("  -E\n")
	_("    Use POSIX Extended Regular Expressions syntax.\n")
	_("    REG_EXTENDED is passed as the cflag to regexec.\n")
	_("  -I\n")
	_("    Ignore case.\n")
	_("    REG_ICASE is passed as the cflag to regexec.\n")
	_("  -Z (default)\n")
	_("    Anchors match newlines.\n")
	_("    REG_NEWLINE is passed as the cflag to regexec.\n")
	_("  -z\n")
	_("    Anchors only match the start or end of the string not newlines, negates -Z flag.\n")
	_("    You can still use newlines in the FIND string, different from sed.\n")
	_("    REG_NEWLINE is not passed as the cflag to regexec.\n")
	_("\n")
	_("FIND and REPLACE shall be placed in that exact order.\n")
	_("\n")
	_("\\b, \\f, \\n, \\r, \\t, \\v, and \\ooo (octal) in FIND and REPLACE will be unescaped.\n")
	_("Otherwise, unescaped backslashes will be removed, so use two backslashes for a backslash.\n")
	_("For example: '\\\\(this\\\\)' and '\\\\1' instead of '\\(this\\)' and '\\1', unlike what\n")
	_("you would do with sed.\n")
	_("\n")
	_("Filenames shall not start with - as they will be interpreted as a flag.\n")
	_("\n")
	_("Single character flags starting with a single dash can be combined.\n")
	_("For example: -EI is equal to -E -I.\n")
	_("\n")
	_("-E (Extended Regex) and -I (ignore case) imply -R (Regex), so using -E or -I automatically\n")
	_("enables -R.\n")
	_("\n")
	_("If no file was passed, read from stdin.\n");

/* clang-format on */

int
main(int argc, char **argv)
{
	/* FIND/REPLACE are the first two arguments; missing -> print usage. */
	if (jstr_nullchk(argv[1])) {
		fprintf(stderr, "%s", usage);
		return EXIT_FAILURE;
	}
	if (jstr_nullchk(argv[2])) {
		/* Only one extra argument: treat "-h" as help, otherwise usage error. */
		FILE *fp = stderr;
		int ret = EXIT_FAILURE;
		if (!strcmp(argv[1], "-h")) {
			fp = stdout;
			ret = EXIT_SUCCESS;
		}
		fprintf(fp, "%s", usage);
		return ret;
	}
	struct stat st;
	int ret;
	args_ty a;
	matcher_args_ty m;
	jstr_twoway_ty t;
	a.t = &t;
	a.find = (const char *)FIND;
	a.rplc = (const char *)RPLC;
	/* Unescape \n, \t, ... in place; the unescaped length is the diff. */
	a.find_len = JSTR_DIFF(jstr_unescape_p(FIND), FIND);
	a.rplc_len = JSTR_DIFF(jstr_unescape_p(RPLC), RPLC);
	m.include_glob = NULL;
	m.exclude_glob = NULL;
	jstr_ty buf = JSTR_INIT;
	init_defaults();
	/* -c does two full passes: pass 1 (G.confirm_pass=1) only scans and
	 * previews while collecting the file list; pass 2 (after 'y') re-reads
	 * and edits each cached file. */
	G.confirm_pass = 1;
	int end_of_flags = 0;
	unsigned int i;
	/* Process all arguments: flags then files, in order. */
	for (i = 3; ARG; ++i) {
		if (*ARG == '-' && !end_of_flags) {
			/* -i[SUFFIX] */
			if (ARG[1] == 'i') {
				/* Plain -i: rewrite the file in place (no backup). */
				if (ARG[2] == '\0') {
					G.mode = (G.mode & ~MODE_PRINT_STDOUT) | MODE_PRINT_FILE;
				} else {
					/* -iSUFFIX: keep the original as FILE + SUFFIX backup. */
					G.bak_suffix = ARG + sizeof("-i") - 1;
					G.bak_suffix_len = strlen(G.bak_suffix);
					G.mode = (G.mode & ~MODE_PRINT_STDOUT) | MODE_PRINT_FILE_BACKUP;
				}
			/* -- flag */
			} else if (ARG[1] == '-') {
				/* --include */
				if (!strcmp(ARG + 2, "include")) {
					ARG_NEXT();
					if (jstr_nullchk(ARG))
						jstr_errdie("%s: %s", argv[0], "no argument after --include flag.\n");
					m.include_glob = ARG;
				}
				/* --exclude */
				if (!strcmp(ARG + 2, "exclude")) {
					ARG_NEXT();
					if (jstr_nullchk(ARG))
						jstr_errdie("%s: %s", argv[0], "no argument after --exclude flag.\n");
					m.exclude_glob = ARG;
				}
				/* bare "--": stop flag parsing */
				if (ARG[2] == '\0') {
					end_of_flags = 1;
				}
			/* Single-dash flags, allow combinations */
			} else {
				const char *argp = ARG + 1;
				for (;; ++argp) {
					switch (*argp) {
					case '\0':
						goto done_single;
					case 'E':
						G.cflags |= JSTR_RE_CF_EXTENDED;
						goto use_regex_flag;
					case 'F':
						G.mode &= ~MODE_USE_REGEX;
						break;
					case 'G':
						G.n = 1;
						break;
					case 'I':
						G.cflags |= JSTR_RE_CF_ICASE;
						goto use_regex_flag;
					case 'R':
						/* -E and -I imply -R: fall through to enable regex mode. */
use_regex_flag:
						G.mode |= MODE_USE_REGEX;
						break;
					case 'Z':
						G.cflags |= JSTR_RE_CF_NEWLINE;
						break;
					case 'c':
						G.mode |= MODE_CONFIRM;
						break;
					case 'g':
						G.n = (size_t)-1;
						break;
					case 'h':
						printf("%s", usage);
						exit(EXIT_SUCCESS);
						break;
					case 'l':
						G.mode |= MODE_PRINT_CHANGES;
						break;
					case 'r':
						G.mode |= MODE_USE_RECURSIVE;
						break;
					case 'z':
						G.cflags &= ~JSTR_RE_CF_NEWLINE;
						break;
					default:
						fprintf(stderr, "find-and-replace: invalid flag '-%c'. See usage below:\n\n%s", *argp, usage);
						exit(EXIT_FAILURE);
						break;
					}
				}
done_single:;
			}
		}
		/* Non-flag argument: a file (or directory with -r) to process. */
		G.mode |= MODE_HAVE_FILES;
		ret = xstat(ARG, &st);
		DIE_IF(ret == JSTR_RET_ERR, "stat(%s) failed.\n", ARG);
		DIE_IF(jstr_chk(compile(&t, a.find, a.find_len)), "%s", "");
		if (IS_REG(st.st_mode)) {
			const size_t fname_len = strlen(ARG);
			if (!m.exclude_glob) {
process:
				DIE_IF(jstr_chk(process_file(&t, &buf, ARG, fname_len, &st, a.find, a.find_len, a.rplc, a.rplc_len)), "find-and-replace: error processing '%s' (find=\"%s\", replace=\"%s\").\n", ARG, a.find, a.rplc);
			} else {
				/* --exclude also filters files named on the command line. */
				const char *fname = jstr_memrchr(ARG, SEP, fname_len);
				fname = (fname != NULL && *(fname + 1)) ? fname + 1 : ARG;
				if (fnmatch(m.exclude_glob, fname, 0))
					goto process;
			}
		} else if (IS_DIR(st.st_mode)) {
			/* Directories are only followed with -r; --include/--exclude are
			 * enforced by the ftw matcher during the traversal. */
			if (G.mode & MODE_USE_RECURSIVE) {
				a.buf = &buf;
				DIE_IF(jstr_chk(jstr_io_ftw(ARG, callback_file, &a, JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG, (m.include_glob || m.exclude_glob) ? matcher : NULL, &m)), "ftw(directory: %s, callback, func_args, flags: JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG, matcher: %s, matcher_args) failed.\n", ARG, m.include_glob ? "1" : "0");
			}
		} else {
			fprintf(stderr, "find-and-replace: %s is not a regular file or directory.\n", ARG);
			exit(EXIT_FAILURE);
		}
	}
	/* End of the -c dry-run pass: no file has been touched yet. */
	if (G.confirm_pass && (G.mode & MODE_CONFIRM)) {
		if (!(G.mode & (MODE_PRINT_FILE | MODE_PRINT_FILE_BACKUP)))
			jstr_errdie("%s: -c requires -i.\n", argv[0]);
		if (!(G.mode & MODE_HAVE_FILES))
			jstr_errdie("%s: -c does not work with stdin.\n", argv[0]);
		if (G.matches_found) {
			jstr_io_fwrite(CONFIRM_PROMPT, 1, S_LEN(CONFIRM_PROMPT), stdout);
			jstr_io_fflush(stdout);
			/* Only an explicit 'y' proceeds; anything else aborts and leaves
			 * every file untouched. */
			if (jstr_io_getchar() != 'y') {
				jstr_io_fwrite(CONFIRM_ABORTED, 1, S_LEN(CONFIRM_ABORTED), stderr);
				exit(EXIT_FAILURE);
			}
			/* Second pass: edit each cached file's content from memory; the
			 * buffers were read once during the scan, so no re-stat or
			 * re-read is needed. The regex/twoway stay compiled. */
			G.confirm_pass = 0;
			G.matches_found = 0;
			for (i = 0; i < G.files.size; ++i)
				if (jstr_chk(process_buffer(&t, &G.files.data[i].content, G.files.data[i].fname, G.files.data[i].fname_len, &G.files.data[i].st, a.find, a.find_len, a.rplc, a.rplc_len)))
					jstr_errdie("find-and-replace: error processing '%s' (find=\"%s\", replace=\"%s\").\n", G.files.data[i].fname, a.find, a.rplc);
			return EXIT_SUCCESS;
		}
		return EXIT_SUCCESS;
	}
	/* If no file was passed, read from stdin. */
	if (!(G.mode & MODE_HAVE_FILES)) {
		/* In-place output and backups are meaningless without a real file. */
		if (jstr_unlikely(G.bak_suffix != NULL) || jstr_unlikely(!(G.mode & MODE_PRINT_STDOUT)))
			jstr_errdie("%s: %s", argv[0], "find-and-replace: trying to create a backup file while reading from stdin.");
		if (jstr_unlikely(G.mode & MODE_USE_RECURSIVE))
			jstr_errdie("%s: %s", argv[0], "trying to recursively traverse through directories while reading from stdin.");
		DIE_IF(jstr_chk(jstr_io_readstdin_j(&buf)), "%s", "Failed reading stdin.\n");
		DIE_IF(jstr_chk(compile(&t, a.find, a.find_len)), "%s", "");
		DIE_IF(jstr_chk(process_buffer(&t, &buf, NULL, 0, NULL, a.find, a.find_len, a.rplc, a.rplc_len)), "%s", "Failed processing stdin.\n");
	}
#if DO_FREE /* We don't need to free since we're exiting. */
	for (i = 0; i < G.files.size; ++i)
		if (free(G.files.data[i].content))
	free(G.files.data);
	free(G.matches.data);
	jstr_re_free(&G.regex);
	jstr_free_j(&buf);
#endif
	return EXIT_SUCCESS;
	(void)argc;
}
