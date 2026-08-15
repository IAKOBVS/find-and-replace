/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef CONFIRM_H
#define CONFIRM_H

#include "common.h"

/* ANSI escape codes used to highlight the -c confirm mode preview. */
#define COLOR_RED       "\x1b[31m"
#define COLOR_GREEN     "\x1b[32m"
#define COLOR_RESET     "\x1b[0m"
#define CONFIRM_PROMPT  "Confirm changes? [y/N]: "
#define CONFIRM_ABORTED "Aborted.\n"
#define MATCHES_CAP_MIN 8

/* Interactive TUI fields. FIELD_COUNT must match the order of the buffers
 * passed to confirm_interactive_loop. */
typedef enum {
	FIELD_FIND,
	FIELD_RPLC,
	FIELD_FLAGS,
	FIELD_FILES,
	FIELD_INCLUDE,
	FIELD_EXCLUDE,
	FIELD_BACKUP,
	FIELD_COUNT
} field_ty;

typedef struct line_counter_ty {
	const char *data;
	size_t pos;  /* Offset up to which LINE is already known. */
	size_t line; /* 1-based line number of the byte at POS. */
} line_counter_ty;

void match_pushback(matches_ty *R matches, size_t start, size_t end, const regmatch_t *rm);
void print_size_t(size_t val);
size_t line_get_start(const char *R data, size_t size, size_t idx);
size_t line_get_end(const char *R data, size_t size, size_t idx);
size_t match_line_end(const char *R data, size_t size, size_t start, size_t end);
void line_counter_init(line_counter_ty *st, const char *R data);
size_t line_counter_get(line_counter_ty *st, size_t idx);

/* -c dry-run scan that collects matches and prints the preview. */
jstr_ret_ty confirm_scan_file(const jstr_twoway_ty *R t,
                              const jstr_ty *R buf, const char *R fname,
                              size_t fname_len, const char *R find,
                              size_t find_len, const char *R rplc,
                              size_t rplc_len, size_t *R out_matches);

jstr_ret_ty confirm_interactive_loop(jstr_twoway_ty *R t,
                                     jstr_ty *R find_buf,
                                     jstr_ty *R rplc_buf,
                                     jstr_ty *R flags_buf,
                                     jstr_ty *R files_buf,
                                     jstr_ty *R include_buf,
                                     jstr_ty *R exclude_buf,
                                     jstr_ty *R backup_buf);

#endif /* CONFIRM_H */
