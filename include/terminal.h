/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef TERMINAL_H
#define TERMINAL_H

#include "common.h"
#include "ui.h"
#include "thread_compat.h"

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


/**
 * @brief Report whether terminal raw mode is active.
 *
 * @details Contract for the public declaration in terminal.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Nonzero when the condition holds; zero otherwise.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @sideeffects Only objects, queues, files, and global state named by the owning contract are modified.
 * @thread Stage C only.
 */
int terminal_active(void);
/**
 * @brief Return the cached terminal column count.
 *
 * @details Contract for the public declaration in terminal.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @sideeffects Only objects, queues, files, and global state named by the owning contract are modified.
 * @thread Stage C only.
 */
unsigned short terminal_cols(void);
/**
 * @brief Return the cached terminal row count.
 *
 * @details Contract for the public declaration in terminal.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @sideeffects Only objects, queues, files, and global state named by the owning contract are modified.
 * @thread Stage C only.
 */
unsigned short terminal_rows(void);

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

/**
 * @brief Run the confirm TUI until selection or abort.
 * @details Edits all seven fields with a 200 ms idle debounce; renders bounded
 *          previews and recompiles filters/live find as fields change.
 * @pre Terminal raw mode is active and all field buffers are initialized.
 * @param t Compiled matcher used for live preview.
 * @param find_buf Editable FIND buffer.
 * @param rplc_buf Editable REPLACE buffer.
 * @param flags_buf Editable FLAGS buffer.
 * @param files_buf Editable Files substring buffer.
 * @param include_buf Editable include regex buffer.
 * @param exclude_buf Editable exclude regex buffer.
 * @param backup_buf Editable backup suffix buffer.
 * @return `JSTR_RET_SUCC` on selection or clean quit.
 * @post G reflects the final field values.
 * @sideeffects Writes terminal escape sequences; mutates G preview state.
 * @thread Stage C only.
 */
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
/**
 * @brief Run the capped live grep TUI until quit or completion.
 * @details Polls UI commands and D match batches between 20 ms key waits,
 *          uses a 200 ms edit debounce, and blanks the preview when a rescan starts.
 * @pre Terminal raw mode is active; D is running.
 * @param t Compiled matcher.
 * @param find_buf Editable FIND buffer.
 * @param files_buf Editable Files filter buffer.
 * @param include_buf Editable include regex buffer.
 * @param exclude_buf Editable exclude regex buffer.
 * @return `JSTR_RET_SUCC` on quit/selection.
 * @post Selected match is emitted by the caller when appropriate.
 * @sideeffects Writes terminal escape sequences; sends config to D.
 * @thread Stage C UI thread.
 */
jstr_ret_ty grep_interactive_loop(jstr_twoway_ty *R t,
                                   jstr_ty *R find_buf,
                                   jstr_ty *R files_buf,
                                   jstr_ty *R include_buf,
                                   jstr_ty *R exclude_buf,
                                   root_ctx_ty *R root);
/**
 * @brief Dedicated Stage-C UI thread.
 *
 * @details Contract for the public declaration in terminal.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param arg parameter defined by the owning contract.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @sideeffects Only objects, queues, files, and global state named by the owning contract are modified.
 * @thread Stage C only.
 */
far_thread_ret_ty terminal_ui_thread(void *arg);

#endif /* TERMINAL_H */

