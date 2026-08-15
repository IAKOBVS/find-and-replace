/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef CONFIRM_H
#define CONFIRM_H

#include "common.h"

/* ANSI escape codes used to highlight the -c confirm mode preview. */
#define COLOR_RED               "\x1b[31m"
#define COLOR_GREEN             "\x1b[32m"
#define COLOR_RESET             "\x1b[0m"
#define ANSI_ALT_SCREEN_ENABLE  "\x1b[?1049h"
#define ANSI_ALT_SCREEN_DISABLE "\x1b[?1049l"
#define ANSI_CLEAR_SCREEN       "\x1b[2J"
#define ANSI_HOME               "\x1b[H"
#define ANSI_CLEAR_LINE_END     "\x1b[K"
#define ANSI_CLEAR_DOWN         "\x1b[J"
#define ANSI_CURSOR_SHOW        "\x1b[?25h"
#define ANSI_CURSOR_HIDE        "\x1b[?25l"

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

typedef enum {
	KEY_NONE,
	KEY_ENTER,
	KEY_TAB,
	KEY_SHIFT_TAB,
	KEY_BACKSPACE,
	KEY_DELETE,
	KEY_ESC,
	KEY_UP,
	KEY_DOWN,
	KEY_LEFT,
	KEY_RIGHT,
	KEY_CTRL_C,
	KEY_CTRL_D,
	KEY_CTRL_J,
	KEY_CTRL_K,
	KEY_CTRL_U,
	KEY_CHAR
} confirm_key_ty;

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
