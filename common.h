/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef COMMON_H
#define COMMON_H

#define JSTR_PANIC                 0
#define JSTR_USE_UNLOCKED_IO_READ  1
#define JSTR_USE_UNLOCKED_IO_WRITE 1

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

/* Die-with-message helper used in every translation unit. */
#define DIE_IF_PRINT(x, fmt, ...)                      \
	do {                                           \
		if (jstr_unlikely(x))                  \
			jstr_errdie(fmt, __VA_ARGS__); \
	} while (0)
#define DIE_IF(x, fmt, ...) DIE_IF_PRINT(x, fmt, __VA_ARGS__)
#define DIE()               DIE_IF(1)
#define R                   JSTR_RESTRICT

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
	int compiled_regex;
	int compiled_cflags;
	/* Set by the scan pass when at least one match exists; decides whether the
	 * confirmation prompt is shown. */
	unsigned int matches_found;
	/* 1 when --grep found at least one matching line; decides the exit code
	 * (0 vs 1). Set even with -q, which only silences the line output. */
	int grep_matched;
	/* 1 while in the -c dry-run pass: process_file only scans/reports matches
	 * instead of modifying files. Reset before the second (real) pass. */
	int confirm_pass;
	/* 1 when --grep + tty: process_file caches files instead of printing
	 * so the grep TUI can scan them interactively. */
	int grep_collect;
	/* 1 when --include/--exclude were given (or edited in the confirm TUI);
	 * guards use of the compiled include_re/exclude_re. */
	int have_include;
	int have_exclude;
	size_t n;
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
	/* 1 when the -c preview scan hit its match budget and stopped early; the
	 * TUI stats then show "N+ matches, M+ files" and scanning further files
	 * stops. Reset by each preview consumer before it scans. */
	int preview_full;
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
} global_ty;

extern global_ty G;

#endif /* COMMON_H */
