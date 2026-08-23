/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef CONFIRM_H
#define CONFIRM_H

#include "common.h"

/* ANSI escape codes used by -c confirm mode and --grep mode. */
#define COLOR_BLACK             "\x1b[30m"
#define COLOR_RED               "\x1b[31m"
#define COLOR_GREEN             "\x1b[32m"
#define COLOR_YELLOW            "\x1b[33m"
#define COLOR_BLUE              "\x1b[34m"
#define COLOR_MAGENTA           "\x1b[35m"
#define COLOR_CYAN              "\x1b[36m"
#define COLOR_WHITE             "\x1b[37m"
#define COLOR_BRIGHT_BLACK      "\x1b[90m"
#define COLOR_BRIGHT_RED        "\x1b[91m"
#define COLOR_BRIGHT_GREEN      "\x1b[92m"
#define COLOR_BRIGHT_YELLOW     "\x1b[93m"
#define COLOR_BRIGHT_BLUE       "\x1b[94m"
#define COLOR_BRIGHT_MAGENTA    "\x1b[95m"
#define COLOR_BRIGHT_CYAN       "\x1b[96m"
#define COLOR_BRIGHT_WHITE      "\x1b[97m"
#define COLOR_BG_BLACK          "\x1b[40m"
#define COLOR_BG_RED            "\x1b[41m"
#define COLOR_BG_GREEN          "\x1b[42m"
#define COLOR_BG_YELLOW         "\x1b[43m"
#define COLOR_BG_BLUE           "\x1b[44m"
#define COLOR_BG_MAGENTA        "\x1b[45m"
#define COLOR_BG_CYAN           "\x1b[46m"
#define COLOR_BG_WHITE          "\x1b[47m"
#define COLOR_BG_BRIGHT_BLACK   "\x1b[100m"
#define COLOR_BG_BRIGHT_RED     "\x1b[101m"
#define COLOR_BG_BRIGHT_GREEN   "\x1b[102m"
#define COLOR_BG_BRIGHT_YELLOW  "\x1b[103m"
#define COLOR_BG_BRIGHT_BLUE    "\x1b[104m"
#define COLOR_BG_BRIGHT_MAGENTA "\x1b[105m"
#define COLOR_BG_BRIGHT_CYAN    "\x1b[106m"
#define COLOR_BG_BRIGHT_WHITE   "\x1b[107m"
#define COLOR_RESET             "\x1b[0m"
#define COLOR_BOLD              "\x1b[1m"
#define COLOR_DIM               "\x1b[2m"
#define COLOR_ITALIC            "\x1b[3m"
#define COLOR_UNDERLINE         "\x1b[4m"
#define COLOR_BLINK             "\x1b[5m"
#define COLOR_NEGATIVE          "\x1b[7m"
#define COLOR_HIDDEN            "\x1b[8m"
#define COLOR_STRIKETHROUGH     "\x1b[9m"
#define COLOR_FG_DEFAULT        "\x1b[39m"
#define COLOR_BG_DEFAULT        "\x1b[49m"
#define COLOR_BOLD_OFF          "\x1b[22m"
#define COLOR_ITALIC_OFF        "\x1b[23m"
#define COLOR_UNDERLINE_OFF     "\x1b[24m"
#define COLOR_BLINK_OFF         "\x1b[25m"
#define COLOR_POSITIVE          "\x1b[27m"
#define COLOR_HIDDEN_OFF        "\x1b[28m"
#define COLOR_STRIKETHROUGH_OFF "\x1b[29m"

/* --grep palette. */
#define TUI_GREP_FILENAME       COLOR_RED
#define TUI_GREP_LINENUMBER     COLOR_GREEN
#define TUI_GREP_MATCHED        COLOR_RED
#define TUI_GREP_UNMATCHED      COLOR_RESET

/* -c confirm preview palette: the FNAME:LINE: prefix elements and the
 * matched substring are tinted with the removed(-)/added(+) side's color;
 * body text is unmatched. */
#define TUI_CONFIRM_FILENAME_REMOVED   COLOR_RED
#define TUI_CONFIRM_FILENAME_ADDED     COLOR_GREEN
#define TUI_CONFIRM_LINENUMBER_REMOVED COLOR_RED
#define TUI_CONFIRM_LINENUMBER_ADDED   COLOR_GREEN
#define TUI_CONFIRM_MATCHED_REMOVED    COLOR_RED
#define TUI_CONFIRM_MATCHED_ADDED      COLOR_GREEN
#define TUI_CONFIRM_UNMATCHED          COLOR_RESET

/* Terminal control escape sequences (fixed strings; parameterized cursor
 * addressing is emitted by term_move_cursor via ANSI_CSI). */
#define ANSI_ESC                "\x1b"
#define ANSI_CSI                "\x1b["
#define ANSI_RESET              "\x1bc"
#define ANSI_ALT_SCREEN_ENABLE  "\x1b[?1049h"
#define ANSI_ALT_SCREEN_DISABLE "\x1b[?1049l"
#define ANSI_CLEAR_SCREEN       "\x1b[2J"
#define ANSI_HOME               "\x1b[H"
#define ANSI_CLEAR_DOWN         "\x1b[J"
#define ANSI_CLEAR_UP           "\x1b[1J"
#define ANSI_CLEAR_LINE         "\x1b[2K"
#define ANSI_CLEAR_LINE_END     "\x1b[K"
#define ANSI_CLEAR_LINE_START   "\x1b[1K"
#define ANSI_CURSOR_SAVE        "\x1b[s"
#define ANSI_CURSOR_RESTORE     "\x1b[u"
#define ANSI_CURSOR_SHOW        "\x1b[?25h"
#define ANSI_CURSOR_HIDE        "\x1b[?25l"
#define ANSI_CURSOR_NEXT_LINE   "\x1b[E"
#define ANSI_CURSOR_PREV_LINE   "\x1b[F"
#define ANSI_SCROLL_UP          "\x1b[S"
#define ANSI_SCROLL_DOWN        "\x1b[T"
#define ANSI_WRAP_ENABLE        "\x1b[?7h"
#define ANSI_WRAP_DISABLE       "\x1b[?7l"
#define ANSI_MOUSE_ENABLE       "\x1b[?1000h"
#define ANSI_MOUSE_DISABLE      "\x1b[?1000l"
#define ANSI_MOUSE_SGR_ENABLE   "\x1b[?1006h"
#define ANSI_MOUSE_SGR_DISABLE  "\x1b[?1006l"
#define ANSI_BRACKETED_PASTE_ENABLE  "\x1b[?2004h"
#define ANSI_BRACKETED_PASTE_DISABLE "\x1b[?2004l"
#define ANSI_APPLICATION_KEYPAD "\x1b="
#define ANSI_NUMERIC_KEYPAD     "\x1b>"

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
	KEY_ALT_J,
	KEY_ALT_K,
	KEY_CTRL_U,
	KEY_CHAR
} confirm_key_ty;

/* Write VAL in decimal to stdout without using printf. */
void
print_size_t(size_t val);

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

/* --grep TUI: scrollable match browser. Prints the selected line to stdout
 * on Enter, exits 0. Ctrl-C/D exits without printing. */
jstr_ret_ty grep_interactive_loop(jstr_twoway_ty *R t,
                                   jstr_ty *R find_buf,
                                   jstr_ty *R files_buf,
                                   jstr_ty *R include_buf,
                                   jstr_ty *R exclude_buf);

#endif /* CONFIRM_H */
