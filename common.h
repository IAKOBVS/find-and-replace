/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef COMMON_H
#define COMMON_H

#define JSTR_PANIC                 0
#define JSTR_USE_UNLOCKED_IO_READ  1
#define JSTR_USE_UNLOCKED_IO_WRITE 0

/* CLI applications exit immediately after use, so buffer frees before exit are
 * pure overhead. 0 = skip freeing in cleanup() paths (leaks are reclaimed by
 * the OS); set to 1 to enable them (e.g. for valgrind/ASan debugging). */
#define DO_FREE 0

#include <jstr/jstr.h>
#include <jstr/io.h>
#include <jstr/regex.h>
#include <jstr/stdstring.h>
#include <unistd.h>

#define S_LEN(s)     (sizeof(s) - 1)
#define S_LITERAL(s) (s), (sizeof(s) - 1)

/* Backreference capture count jstring's regex engine supports (its internal
 * rm[] array holds 10 entries). Every nmatch argument and the tool's own
 * match_ty.rm[] must stay in sync with this. */
#define JSTR_NMATCH_MAX 10

/* Upper bound for -j/--jobs (worker threads in the recursive pipeline). */
#define FAR_JOBS_MAX 1024

/* Fatal per-file error capture for the threaded pipeline. Workers may not
 * touch stdio streams or call exit(), so processing functions take a
 * proc_err_ty: non-NULL means "render the fatal message here and return
 * JSTR_RET_ERR"; NULL keeps the historic die-on-the-spot behavior. The buffer
 * must hold the longest messages verbatim (they embed a full PATH_MAX path). */
#define PROC_ERR_MSG_MAX (JSTR_IO_PATH_MAX + 256)
typedef struct proc_err_ty {
	char buf[PROC_ERR_MSG_MAX];
	int set;
} proc_err_ty;

/* Boolean state bits for global_ty.gflags. */
#define F_COMPILED_RE   (1u << 0) /* find matcher compiled as a regex (else Two-Way) */
#define F_MATCHES_FOUND (1u << 1) /* -c dry-run pass produced at least one match */
#define F_GREP_MATCHED  (1u << 2) /* --grep saw a matching line (drives exit code; -q still sets it) */
#define F_CONFIRM_PASS  (1u << 3) /* inside the -c dry-run pass */
#define F_GREP_COLLECT  (1u << 4) /* tty --grep caches files for the interactive TUI */
#define F_HAVE_INCLUDE  (1u << 5) /* include filter compiled and active */
#define F_HAVE_EXCLUDE  (1u << 6) /* exclude filter compiled and active */
#define F_PREVIEW_FULL  (1u << 7) /* -c preview scan hit its budget ("N+ matches" stats) */

/* Die-with-message helper used in every translation unit. */
#define DIE_IF_PRINT(x, fmt, ...)                      \
	do {                                           \
		if (jstr_unlikely(x))                  \
			jstr_errdie(fmt, __VA_ARGS__); \
	} while (0)
#define DIE_IF(x, fmt, ...) DIE_IF_PRINT(x, fmt, __VA_ARGS__)
#define DIE()               DIE_IF(1)
#define R                   JSTR_RESTRICT

typedef struct range_ty {
	size_t start;
	size_t end;
} range_ty;

typedef struct ranges_ty {
	size_t cap;
	size_t size;
	range_ty *data;
} ranges_ty;

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
	MODE_GREP = 1 << 9,
	MODE_QUIET = 1 << 10,
} mode_ty;

/* One byte range of a find occurrence, relative to the start of the file. */
typedef struct match_ty {
	size_t start;
	size_t end;
	regmatch_t rm[JSTR_NMATCH_MAX];
} match_ty;

typedef struct matches_ty {
	size_t cap;
	size_t size;
	match_ty *data;
} matches_ty;

/* A single matching line collected for the grep TUI. Pointers into file
 * content buffers are stable across the scan (files are cached in G.files). */
typedef struct grep_line_ty {
	const char *fname;
	size_t fname_len;
	size_t line_num;
	const char *content;
	size_t content_len;
	size_t match_off;
	size_t match_len;
} grep_line_ty;

typedef struct grep_lines_ty {
	size_t cap;
	size_t size;
	grep_line_ty *data;
} grep_lines_ty;

/* One file collected during the -c scan pass: its name, stat, and full
 * content. The content buffer is stolen from the shared buf so pass 2 edits
 * it from memory instead of re-walking argv/ftw or re-reading the file. */
typedef struct file_ty {
	char *fname;
	size_t fname_len;
	size_t content_size;
	unsigned int st_mode;
	jstr_ty content;
} file_ty;

typedef struct files_ty {
	size_t cap;
	size_t size;
	size_t total_content_size;
	file_ty *data;
} files_ty;

/* Process-wide settings gathered from the command line. Fields are ordered
 * for cache locality: hot scalars and the buffers touched together in the
 * confirm scan loop come first, large and rarely-read state goes last. */
typedef struct global_ty {
	int mode;
	int eflags;
	int cflags;
	/* State under which the find matcher was last compiled, so compile()
	 * recompiles when flags flip between files mid-command-line. */
	int compiled_cflags;
	/* Boolean state packed into one byte so the hot fields of the global sit
	 * on fewer cache lines during scanning. */
	unsigned char gflags;
	size_t n;
	/* Worker count for the threaded recursive pipeline (-j/--jobs). */
	size_t jobs;
	size_t bak_suffix_len;
	/* Frequently-touched growable state, grouped so the match list and the
	 * preview buffers' headers sit on the same cache lines while scanning. */
	matches_ty matches;
	jstr_ty rplc_buf;
	/* Cached output of the previous -c preview hunk; emptied per block but
	 * the allocation is reused across files so capacity persists. */
	jstr_ty new_buf;
	jstr_ty content_buf;
	/* Cached interactive TUI buffers */
	jstr_ty interactive_find_buf;
	jstr_ty interactive_rplc_buf;
	jstr_ty interactive_flags_buf;
	jstr_ty interactive_files_buf;
	jstr_ty interactive_include_buf;
	jstr_ty interactive_exclude_buf;
	jstr_ty interactive_backup_buf;
	/* Dynamically calculated file cache limit */
	size_t file_cache_max;
	/* Dynamic tracking of preview line usage in interactive mode */
	size_t preview_lines_printed;
	size_t max_preview_lines;
	/* Scroll state for the interactive preview. */
	size_t scroll_offset;
	size_t selected_line;
	size_t total_lines;
	/* Grep TUI match collection (no budget limit). */
	grep_lines_ty grep_lines;
	/* Cold configuration, read only during startup and traversal. */
	const char *include_pat;
	const char *exclude_pat;
	const char *bak_suffix;
	/* Growable list of files to edit once the user confirms. */
	files_ty files;
	/* Compiled regexes for the find pattern and the --include/--exclude
	 * basename filters; largest members, touched only in regex mode. */
	jstr_re_ty regex;
	jstr_re_ty include_re;
	jstr_re_ty exclude_re;
	ranges_ty old_ranges;
	ranges_ty new_ranges;
	jstr_ty find_plain;
	jstr_ty rplc_plain;
} global_ty;

extern global_ty G;

jstr_ret_ty far_compile(jstr_twoway_ty *R t, const char *R find, size_t find_len, const char *R rplc, size_t rplc_len, int force_recompile, char *err_buf, size_t err_size);

#endif /* COMMON_H */
