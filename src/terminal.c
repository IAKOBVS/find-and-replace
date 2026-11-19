/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "terminal.h"
#include "process.h"
#include "pipeline.h"
#include "vim.h"

#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

static struct termios orig_termios;
typedef enum {
	TERM_OFF,
	TERM_RAW,
	TERM_RESTORING
} term_state_ty;

static term_state_ty term_state = TERM_OFF;
static const char *env_cols;
static const char *env_lines;
static int ui_stop_requested;
static int esc_char_pending;

#define TERM_ROWS_FALLBACK 24
#define TERM_COLS_FALLBACK 80

/**
 * @brief Restore the terminal from raw mode.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
restore_terminal(void)
{
	if (term_state == TERM_RAW) {
		term_state = TERM_RESTORING;
		tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
		/* Use async-signal-safe write for signal safety when leaving alt screen and showing cursor */
		if (jstr_unlikely(write(STDOUT_FILENO, ANSI_ALT_SCREEN_DISABLE ANSI_CURSOR_SHOW, S_LEN(ANSI_ALT_SCREEN_DISABLE ANSI_CURSOR_SHOW)) < 0)) {}
		term_state = TERM_OFF;
	}
}

/**
 * @brief Signal handler that requests TUI shutdown.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param sig parameter defined by the owning module contract.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
handle_signal(int sig)
{
	(void)sig;
	restore_terminal();
	_exit(EXIT_FAILURE);
}

/**
 * @brief Clear the terminal screen.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
term_clear_screen(void)
{
	if (jstr_unlikely(!ui_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_CLEAR_SCREEN, 1, S_LEN(ANSI_CLEAR_SCREEN), stdout);
}

/**
 * @brief Move the cursor to the home position.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
term_home(void)
{
	if (jstr_unlikely(!ui_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_HOME, 1, S_LEN(ANSI_HOME), stdout);
}

/**
 * @brief Clear the screen and home the cursor.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
term_clear_and_home(void)
{
	term_clear_screen();
	term_home();
}

/**
 * @brief Clear from the cursor to end of line.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
term_clear_line_end(void)
{
	if (jstr_unlikely(!ui_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_CLEAR_LINE_END, 1, S_LEN(ANSI_CLEAR_LINE_END), stdout);
}

/**
 * @brief Clear from the cursor to end of screen.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
term_clear_down(void)
{
	if (jstr_unlikely(!ui_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_CLEAR_DOWN, 1, S_LEN(ANSI_CLEAR_DOWN), stdout);
}

/**
 * @brief Make the terminal cursor visible.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
term_show_cursor(void)
{
	if (jstr_unlikely(!ui_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_CURSOR_SHOW, 1, S_LEN(ANSI_CURSOR_SHOW), stdout);
}

/**
 * @brief Hide the terminal cursor.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
term_hide_cursor(void)
{
	if (jstr_unlikely(!ui_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_CURSOR_HIDE, 1, S_LEN(ANSI_CURSOR_HIDE), stdout);
}

/**
 * @brief Move the cursor to a 1-based row and column.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param line destination line buffer or worker queue index.
 * @param col parameter defined by the owning module contract.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
term_move_cursor(size_t line, size_t col)
{
	if (jstr_unlikely(!ui_ok()))
		return;
	(void)jstr_io_fwrite(ANSI_CSI, 1, S_LEN(ANSI_CSI), stdout);
	ui_print_size_t(line);
	(void)jstr_io_putchar(';');
	ui_print_size_t(col);
	(void)jstr_io_putchar('H');
}

/**
 * @brief Enable raw mode and install terminal state.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
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
	term_state = TERM_RAW;
	/* Enter alt screen, clear/home, hide cursor */
	if (jstr_unlikely(jstr_io_fwrite(ANSI_ALT_SCREEN_ENABLE, 1, S_LEN(ANSI_ALT_SCREEN_ENABLE), stdout) != S_LEN(ANSI_ALT_SCREEN_ENABLE))) {
		restore_terminal();
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

/**
 * @brief Return the terminal width with documented fallbacks.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
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

/* Compile the interactive Include/Exclude fields into the global regexes.
 * An empty pattern clears the filter. On invalid regex, report it and return
 * JSTR_RET_ERR so the caller treats the whole session as invalid. */
/**
 * @brief Recompile live include/exclude filters.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param include parameter defined by the owning module contract.
 * @param include_len parameter defined by the owning module contract.
 * @param exclude parameter defined by the owning module contract.
 * @param exclude_len parameter defined by the owning module contract.
 * @param err_buf parameter defined by the owning module contract.
 * @param err_size parameter defined by the owning module contract.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
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
/**
 * @brief Apply the interactive Files substring filter.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param file parameter defined by the owning module contract.
 * @param files_buf Files substring buffer.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
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

/**
 * @brief Parse the confirm TUI FLAGS field into G.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param flags flags buffer.
 * @param len valid byte count.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
parse_interactive_flags(const char *flags, size_t len)
{
	/* Reset to initial configuration default states */
	G.n = 1;
	G.mode &= ~MODE_USE_REGEX;
	G.mode &= ~MODE_PRINT_CHANGES;
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

/**
 * @brief Return the terminal height with documented fallbacks.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
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
/**
 * @brief Return the editable buffer for a confirm field index.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param find_buf FIND field buffer.
 * @param rplc_buf REPLACE field buffer.
 * @param flags_buf parameter defined by the owning module contract.
 * @param files_buf Files substring buffer.
 * @param include_buf include regex buffer.
 * @param exclude_buf exclude regex buffer.
 * @param backup_buf backup suffix buffer.
 * @param field parameter defined by the owning module contract.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
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
/**
 * @brief Report whether editing a field requires recompile.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param field parameter defined by the owning module contract.
 * @return Nonzero when the condition holds; zero otherwise.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
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
/**
 * @brief Copy and unescape an interactive field into a scratch buffer.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param dst parameter defined by the owning module contract.
 * @param src source bytes.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
jstr_unescape_copy(jstr_ty *R dst, const jstr_ty *R src)
{
	jstr_empty_j(dst);
	if (src->size > 0 && src->data) {
		DIE_IF(jstr_chk(jstr_assign_len_j(dst, src->data, src->size)), "%s", "Out of memory.\n");
		dst->size = JSTR_DIFF(jstr_unescape_p(dst->data), dst->data);
	}
}

/**
 * @brief Render one editable confirm field.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param info parameter defined by the owning module contract.
 * @param buf growable byte buffer.
 * @param is_active parameter defined by the owning module contract.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
confirm_render_field(const field_info_ty *info, const jstr_ty *buf, int is_active)
{
	if (jstr_unlikely(!ui_ok()))
		return;
	if (is_active)
		(void)jstr_io_fwrite(info->active_prefix, 1, info->active_prefix_len, stdout);
	else
		(void)jstr_io_fwrite(info->inactive_prefix, 1, info->inactive_prefix_len, stdout);
	if (buf && buf->size > 0 && buf->data)
		(void)jstr_io_fwrite(buf->data, 1, buf->size, stdout);
	term_clear_line_end();
}

/**
 * @brief Read one decoded key from stdin.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param out_char parameter defined by the owning module contract.
 * @return Function result as defined by the return type.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
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
		typedef enum {
			KPARSE_ESC,
			KPARSE_CSI,
			KPARSE_CSI_3
		} key_parse_state_ty;
		struct termios raw;
		tcgetattr(STDIN_FILENO, &raw);
		raw.c_cc[VMIN] = 0;
		raw.c_cc[VTIME] = 1;
		tcsetattr(STDIN_FILENO, TCSANOW, &raw);

		key_parse_state_ty state = KPARSE_ESC;
		char seq[3];
		int n1 = read(STDIN_FILENO, &seq[0], 1);
		int n2 = 0;
		int n3 = 0;
		if (n1 > 0 && (seq[0] == 'j' || seq[0] == 'J')) {
			raw.c_cc[VMIN] = 1;
			raw.c_cc[VTIME] = 0;
			tcsetattr(STDIN_FILENO, TCSANOW, &raw);
			return KEY_ALT_J;
		}
		if (n1 > 0 && (seq[0] == 'k' || seq[0] == 'K')) {
			raw.c_cc[VMIN] = 1;
			raw.c_cc[VTIME] = 0;
			tcsetattr(STDIN_FILENO, TCSANOW, &raw);
			return KEY_ALT_K;
		}
		if (n1 > 0 && seq[0] == '[') {
			state = KPARSE_CSI;
			n2 = read(STDIN_FILENO, &seq[1], 1);
			if (n2 > 0 && seq[1] == '3')
				state = KPARSE_CSI_3;
		}
		if (state == KPARSE_CSI_3)
			n3 = read(STDIN_FILENO, &seq[2], 1);

		raw.c_cc[VMIN] = 1;
		raw.c_cc[VTIME] = 0;
		tcsetattr(STDIN_FILENO, TCSANOW, &raw);

		if (n1 <= 0)
			return KEY_ESC;
		if (state == KPARSE_ESC && seq[0] >= 32 && seq[0] <= 126) {
			*out_char = seq[0];
			esc_char_pending = 1;
			return KEY_CHAR;
		}
		if (state == KPARSE_CSI && n2 > 0) {
			if (seq[1] == 'Z') return KEY_SHIFT_TAB;
			if (seq[1] == 'A') return KEY_UP;
			if (seq[1] == 'B') return KEY_DOWN;
			if (seq[1] == 'D') return KEY_LEFT;
			if (seq[1] == 'C') return KEY_RIGHT;
		}
		if (state == KPARSE_CSI_3 && n3 > 0 && seq[2] == '~')
			return KEY_DELETE;
		return KEY_NONE;
	}

	if ((unsigned char)c >= 32 && (unsigned char)c <= 126)
		return KEY_CHAR;

	return KEY_NONE;
}

/**
 * @brief Read one key with a bounded wait.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param out_char parameter defined by the owning module contract.
 * @param timeout_ms maximum wait in milliseconds.
 * @return Function result as defined by the return type.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static confirm_key_ty
confirm_read_key_timeout(char *out_char, int timeout_ms)
{
	struct pollfd pfd;
	pfd.fd = STDIN_FILENO;
	pfd.events = POLLIN;
	pfd.revents = 0;
	const int ret = poll(&pfd, 1, timeout_ms);
	if (ret <= 0 || !(pfd.revents & POLLIN))
		return KEY_NONE;
	return confirm_read_key(out_char);
}

/**
 * @brief Return a monotonic millisecond timestamp.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Function result as defined by the return type.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static long long
grep_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/**
 * @brief Return a monotonic microsecond timestamp.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Function result as defined by the return type.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static long long
grep_now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static char err_buf[256];
static char last_err_buf[256];

/**
 * @brief Render the TUI marker and Stats line.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param start_control_line parameter defined by the owning module contract.
 * @param total_matches parameter defined by the owning module contract.
 * @param files_matched parameter defined by the owning module contract.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
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
	ui_print_size_t(total_matches);
	if (G.preview_full)
		(void)jstr_io_putchar('+');
	(void)jstr_io_fwrite(" matches, ", 1, S_LEN(" matches, "), stdout);
	ui_print_size_t(files_matched);
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

typedef enum {
	GREP_UI_LIVE,
	GREP_UI_END_PENDING,
	GREP_UI_FINAL,
	GREP_UI_READY,
	GREP_UI_QUIT
} grep_ui_phase_ty;

static const grep_field_info_ty grep_field_info_table[GREP_FIELD_COUNT] = {
	{ "* Find:    ", S_LEN("* Find:    "), "  Find:    ", S_LEN("  Find:    "), 1 },
	{ "* Files:   ", S_LEN("* Files:   "), "  Files:   ", S_LEN("  Files:   "), 1 },
	{ "* Include: ", S_LEN("* Include: "), "  Include: ", S_LEN("  Include: "), 1 },
	{ "* Exclude: ", S_LEN("* Exclude: "), "  Exclude: ", S_LEN("  Exclude: "), 1 },
};

/**
 * @brief Return the editable buffer for a grep field index.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param find_buf FIND field buffer.
 * @param files_buf Files substring buffer.
 * @param include_buf include regex buffer.
 * @param exclude_buf exclude regex buffer.
 * @param field parameter defined by the owning module contract.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
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

/**
 * @brief Report whether editing a grep field requires rescan.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param field parameter defined by the owning module contract.
 * @return Nonzero when the condition holds; zero otherwise.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
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
/**
 * @brief Render one grep match line in the capped TUI.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param gl parameter defined by the owning module contract.
 * @param is_selected parameter defined by the owning module contract.
 * @param cols parameter defined by the owning module contract.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static int
grep_print_line(const grep_line_ty *gl, int is_selected, unsigned short cols)
{
	if (jstr_unlikely(!ui_ok()))
		return 0;
	(void)jstr_io_fwrite(TUI_GREP_FILENAME, 1, S_LEN(TUI_GREP_FILENAME), stdout);
	if (is_selected)
		(void)jstr_io_fwrite(COLOR_NEGATIVE, 1, S_LEN(COLOR_NEGATIVE), stdout);
	(void)jstr_io_fwrite(gl->fname, 1, gl->fname_len, stdout);
	if (is_selected)
		(void)jstr_io_fwrite(COLOR_POSITIVE, 1, S_LEN(COLOR_POSITIVE), stdout);
	(void)jstr_io_fwrite(TUI_GREP_UNMATCHED, 1, S_LEN(TUI_GREP_UNMATCHED), stdout);
	(void)jstr_io_fputc(':', stdout);
	(void)jstr_io_fwrite(TUI_GREP_LINENUMBER, 1, S_LEN(TUI_GREP_LINENUMBER), stdout);
	ui_print_size_t(gl->line_num);
	(void)jstr_io_fwrite(TUI_GREP_UNMATCHED, 1, S_LEN(TUI_GREP_UNMATCHED), stdout);
	(void)jstr_io_fputc(':', stdout);
	(void)jstr_io_fwrite(gl->content, 1, gl->match_off, stdout);
	(void)jstr_io_fwrite(TUI_GREP_MATCHED, 1, S_LEN(TUI_GREP_MATCHED), stdout);
	(void)jstr_io_fwrite(gl->content + gl->match_off, 1, gl->match_len, stdout);
	(void)jstr_io_fwrite(TUI_GREP_UNMATCHED, 1, S_LEN(TUI_GREP_UNMATCHED), stdout);
	const size_t after_off = gl->match_off + gl->match_len;
	const size_t after_len = gl->content_len - after_off;
	if (term_state == TERM_RAW) {
		unsigned short col = (unsigned short)(gl->fname_len + ui_size_t_width(gl->line_num) + 3 + gl->match_off + gl->match_len);
		ui_print_diff_line_chars(gl->content + after_off, after_len, cols, &col);
	} else {
		(void)jstr_io_fwrite(gl->content + after_off, 1, after_len, stdout);
	}
	if (term_state == TERM_RAW)
		(void)jstr_io_fwrite(ANSI_CLEAR_LINE_END, 1, S_LEN(ANSI_CLEAR_LINE_END), stdout);
	(void)jstr_io_putchar('\n');
	return 1;
}

#define GREP_REDRAW_MS 100
#define GREP_RESCAN_DEBOUNCE_MS 200

/**
 * @brief Return the live grep match limit for the terminal height.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static size_t
grep_match_cap(void)
{
	const unsigned short rows = get_terminal_rows();
	const size_t control_lines = GREP_FIELD_COUNT + 3;
	return rows > control_lines ? rows - control_lines : 1;
}

/**
 * @brief Emit the selected grep match after the TUI exits.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
grep_emit_selected(void)
{
	if (G.grep_lines.size == 0 || G.selected_line >= G.grep_lines.size)
		return;
	const grep_line_ty *gl = &G.grep_lines.data[G.selected_line];
	(void)jstr_io_fwrite(COLOR_RED, 1, S_LEN(COLOR_RED), stdout);
	(void)jstr_io_fwrite(gl->fname, 1, gl->fname_len, stdout);
	(void)jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
	(void)jstr_io_fputc(':', stdout);
	(void)jstr_io_fwrite(COLOR_GREEN, 1, S_LEN(COLOR_GREEN), stdout);
	ui_print_size_t(gl->line_num);
	(void)jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout);
	(void)jstr_io_fputc(':', stdout);
	(void)jstr_io_fwrite(gl->content, 1, gl->content_len, stdout);
	(void)jstr_io_fputc('\n', stdout);
}

typedef enum {
	RETIRE_C_PENDING,
	RETIRE_IN_FLIGHT
} retire_owner_ty;

typedef struct grep_retire_node_ty {
	grep_lines_ty lines;
	retire_owner_ty owner;
	struct grep_retire_node_ty *next;
} grep_retire_node_ty;

static grep_retire_node_ty *grep_retire_pending;

/**
 * @brief Move pending retired lists to D without blocking.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static int
grep_retire_flush(void)
{
	while (grep_retire_pending != NULL) {
		grep_retire_node_ty *const node = grep_retire_pending;
		grep_retire_node_ty *const next = node->next;
		node->owner = RETIRE_IN_FLIGHT;
		if (pipeline_grep_retire_try_send(&node->lines) != 0) {
			node->owner = RETIRE_C_PENDING;
			break;
		}
		grep_retire_pending = next;
	}
	return grep_retire_pending != NULL;
}

/**
 * @brief Retire all owned match records in a list.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param lines match list to modify or retire.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
grep_lines_discard(grep_lines_ty *R lines)
{
	if (lines->data == NULL) {
		lines->size = 0;
		lines->cap = 0;
		return;
	}
	grep_retire_node_ty *const node = (grep_retire_node_ty *)malloc(sizeof *node);
	if (jstr_unlikely(!node)) {
		for (size_t i = 0; i < lines->size; ++i)
			free(lines->data[i].owner);
		free(lines->data);
	} else {
		node->lines = *lines;
		node->owner = RETIRE_IN_FLIGHT;
		if (pipeline_grep_retire_try_send(&node->lines) != 0) {
			node->owner = RETIRE_C_PENDING;
			node->next = grep_retire_pending;
			grep_retire_pending = node;
		}
	}
	lines->data = NULL;
	lines->size = 0;
	lines->cap = 0;
}

/**
 * @brief Reserve capacity in a match list.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param lines match list to modify or retire.
 * @param extra parameter defined by the owning module contract.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
grep_lines_reserve(grep_lines_ty *R lines, size_t extra)
{
	if (lines->size + extra <= lines->cap)
		return;
	size_t cap = lines->cap == 0 ? 32 : lines->cap;
	while (cap < lines->size + extra)
		cap *= 2;
	grep_line_ty *const tmp = (grep_line_ty *)realloc(lines->data, cap * sizeof *tmp);
	if (jstr_unlikely(!tmp))
		jstr_errdie("%s", "Out of memory.\n");
	lines->data = tmp;
	lines->cap = cap;
}

/**
 * @brief Append one D batch to a match list.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param lines match list to modify or retire.
 * @param src source bytes.
 * @param n requested capacity.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
grep_lines_append_batch(grep_lines_ty *R lines, const grep_line_ty *R src, size_t n)
{
	grep_lines_reserve(lines, n);
	memcpy(lines->data + lines->size, src, n * sizeof *src);
	lines->size += n;
}

/**
 * @brief Duplicate an editable buffer into an owned C string.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param buf growable byte buffer.
 * @return Owned or borrowed string pointer; `NULL` on failure/EOF where documented.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static char *
grep_dup(const jstr_ty *R buf)
{
	if (buf == NULL || buf->size == 0 || buf->data == NULL)
		return NULL;
	char *const p = (char *)malloc(buf->size + 1);
	if (jstr_unlikely(!p))
		jstr_errdie("%s", "Out of memory.\n");
	memcpy(p, buf->data, buf->size);
	p[buf->size] = '\0';
	return p;
}

/**
 * @brief Build and publish a grep configuration snapshot.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param kind message kind discriminator.
 * @param gen configuration generation.
 * @param limit maximum number of emitted matches.
 * @param find_buf FIND field buffer.
 * @param files_buf Files substring buffer.
 * @param include_buf include regex buffer.
 * @param exclude_buf exclude regex buffer.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
grep_send_cfg(grep_cfg_kind_ty kind, unsigned long gen, size_t limit,
              const jstr_ty *R find_buf, const jstr_ty *R files_buf,
              const jstr_ty *R include_buf, const jstr_ty *R exclude_buf)
{
	grep_cfg_ty *const cfg = (grep_cfg_ty *)calloc(1, sizeof *cfg);
	if (jstr_unlikely(!cfg))
		jstr_errdie("%s", "Out of memory.\n");
	cfg->kind = kind;
	cfg->gen = gen;
	cfg->limit = limit;
	cfg->use_regex = (G.mode & MODE_USE_REGEX) != 0;
	cfg->cflags = G.cflags;
	cfg->eflags = G.eflags;
	cfg->find = grep_dup(find_buf);
	cfg->find_len = cfg->find != NULL ? find_buf->size : 0;
	cfg->files = grep_dup(files_buf);
	cfg->files_len = cfg->files != NULL ? files_buf->size : 0;
	cfg->include = grep_dup(include_buf);
	cfg->include_len = cfg->include != NULL ? include_buf->size : 0;
	cfg->exclude = grep_dup(exclude_buf);
	cfg->exclude_len = cfg->exclude != NULL ? exclude_buf->size : 0;
	if (pipeline_grep_cfg_send(cfg) != 0) {
		free(cfg->find);
		free(cfg->files);
		free(cfg->include);
		free(cfg->exclude);
		free(cfg);
	}
}

/**
 * @brief Run the live grep TUI until quit or completion.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param t compiled fixed-string matcher.
 * @param find_buf FIND field buffer.
 * @param files_buf Files substring buffer.
 * @param include_buf include regex buffer.
 * @param exclude_buf exclude regex buffer.
 * @param root per-root pipeline context.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
jstr_ret_ty
grep_interactive_loop(jstr_twoway_ty *R t,
                       jstr_ty *R find_buf,
                       jstr_ty *R files_buf,
                       jstr_ty *R include_buf,
                       jstr_ty *R exclude_buf,
                       root_ctx_ty *R root)
{
	setup_terminal();
	if (jstr_unlikely(term_state != TERM_RAW))
		return JSTR_RET_SUCC;
	(void)t;
	vim_set_insert_mode(1);

	G.scroll_offset = 0;
	G.selected_line = 0;
	G.total_lines = 0;
	int needs_redraw = 1;
	int needs_rescan = 1;
	int first_draw = 1;
	grep_ui_phase_ty phase = GREP_UI_LIVE;
	int end_requested = 0;
	int pending_enter = 0;
	int quit = 0;
	int rescanning = 0;
	unsigned long grep_gen = 0;
	unsigned long full_rescan_gen = 0;
	root_ctx_ty *current_root = root;
	long long last_redraw = grep_now_ms();
	size_t files_matched = 0;
	size_t last_match_count = 0;
	size_t last_files_matched = 0;
	int visible_dirty = 0;
	long long rescan_due = 0;
	size_t active_field = 0;
	size_t cursors[GREP_FIELD_COUNT];
	cursors[GREP_FIELD_FIND] = find_buf->size;
	cursors[GREP_FIELD_FILES] = files_buf->size;
	cursors[GREP_FIELD_INCLUDE] = include_buf->size;
	cursors[GREP_FIELD_EXCLUDE] = exclude_buf->size;

	for (;;) {
		(void)grep_retire_flush();
		far_ui_cmd_ty *ucmd;
		while ((ucmd = pipeline_ui_cmd_try_recv()) != NULL) {
			if (ucmd->kind == FAR_UI_ROOT) {
				current_root = ucmd->root;
				phase = GREP_UI_LIVE;
				end_requested = 0;
				needs_redraw = 1;
			} else if (ucmd->kind == FAR_UI_END) {
				end_requested = 1;
				if (phase == GREP_UI_LIVE) {
					phase = GREP_UI_END_PENDING;
				} else {
					phase = GREP_UI_FINAL;
					needs_rescan = 1;
					rescan_due = 0;
				}
				needs_redraw = 1;
			} else if (ucmd->kind == FAR_UI_STOP) {
				ui_stop_requested = 1;
				quit = 1;
				if (current_root != NULL)
					atomic_store_explicit(&current_root->cancel, true, memory_order_release);
			}
		}
		far_grep_msg_ty *msg;
		int got_match = 0;
		const long long msg_deadline = grep_now_us() + 1000;
		for (;;) {
			msg = pipeline_grep_msg_try_recv();
			if (msg == NULL)
				break;
			if (msg->kind == FAR_GREP_EOS) {
				if (phase == GREP_UI_END_PENDING) {
					phase = GREP_UI_FINAL;
					needs_rescan = 1;
					rescan_due = 0;
				} else if (phase == GREP_UI_LIVE) {
					phase = GREP_UI_READY;
				}
				current_root = NULL;
				pipeline_ui_ack_send(0);
				needs_redraw = 1;
				free(msg);
				continue;
			}
			if (msg->kind == FAR_GREP_ERROR) {
				if (current_root != NULL)
					++current_root->a->err_count;
				free(msg);
				continue;
			}
			if (msg->gen != grep_gen) {
				for (size_t i = 0; i < msg->count; ++i)
					free(msg->lines[i].owner);
				free(msg->lines);
				free(msg);
				continue;
			}
			if (msg->kind == FAR_GREP_MATCH) {
				grep_lines_append_batch(&G.grep_lines, msg->lines, msg->count);
				files_matched += msg->files_matched;
				got_match = 1;
				free(msg->lines);
				free(msg);
				continue;
			}
			if (msg->kind == FAR_GREP_DONE) {
				if (phase == GREP_UI_FINAL && msg->gen == full_rescan_gen)
					phase = GREP_UI_READY;
				rescanning = 0;
				needs_redraw = 1;
			}
			free(msg);
			if (grep_now_us() >= msg_deadline)
				break;
		}
		if (got_match) {
			G.total_lines = G.grep_lines.size;
			if (G.total_lines > 0 && G.selected_line >= G.total_lines)
				G.selected_line = G.total_lines - 1;
			if (G.grep_lines.size != last_match_count || files_matched != last_files_matched)
				visible_dirty = 1;
		}
		if (visible_dirty && grep_now_ms() - last_redraw >= GREP_REDRAW_MS)
			needs_redraw = 1;
		if (quit) {
			phase = GREP_UI_QUIT;
			pipeline_ui_ack_send(0);
			break;
		}
		if (pending_enter && phase == GREP_UI_READY && !rescanning && !needs_rescan && end_requested) {
			if (G.grep_lines.size > 0) {
				restore_terminal();
				grep_emit_selected();
				pipeline_ui_ack_send(0);
				return JSTR_RET_SUCC;
			}
			pending_enter = 0;
		}
		if (needs_rescan && rescan_due != 0 && grep_now_ms() >= rescan_due)
			needs_redraw = 1;
		if (needs_redraw) {
			if (jstr_unlikely(!ui_ok()))
				break;
			last_redraw = grep_now_ms();
			if (first_draw) {
				term_clear_and_home();
				first_draw = 0;
			} else {
				term_home();
			}

			if (needs_rescan && (rescan_due == 0 || grep_now_ms() >= rescan_due)) {
				++grep_gen;
				if (phase == GREP_UI_FINAL)
					full_rescan_gen = grep_gen;
				grep_lines_discard(&G.grep_lines);
				files_matched = 0;
				G.total_lines = 0;
				G.selected_line = 0;
				G.scroll_offset = 0;
				rescanning = 1;
				rescan_due = 0;
				grep_send_cfg(phase == GREP_UI_FINAL ? GREP_CFG_FULL : GREP_CFG_UPDATE,
				              grep_gen,
				              phase == GREP_UI_FINAL ? (size_t)-1 : grep_match_cap(),
				              find_buf, files_buf, include_buf, exclude_buf);
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
			if (term_state == TERM_RAW)
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
				(void)jstr_io_fwrite(". (more matches below)", 1, S_LEN(". (more matches below)"), stdout);
				term_clear_line_end();
				(void)jstr_io_putchar('\n');
			}

			term_clear_down();

			const size_t start_control_line = (rows > GREP_FIELD_COUNT + 1) ? rows - (GREP_FIELD_COUNT + 1) : 1;

			term_move_cursor(start_control_line, 1);

			if (vim_is_insert_mode()) {
				(void)jstr_io_fwrite("-- [INSERT] --", 1, S_LEN("-- [INSERT] --"), stdout);
			} else {
				(void)jstr_io_fwrite("-- [NORMAL] --", 1, S_LEN("-- [NORMAL] --"), stdout);
			}
			term_clear_line_end();
			(void)jstr_io_putchar('\n');

			(void)jstr_io_fwrite("  Stats:    ", 1, S_LEN("  Stats:    "), stdout);
			ui_print_size_t(G.grep_lines.size);
			(void)jstr_io_fwrite(" matches, ", 1, S_LEN(" matches, "), stdout);

			ui_print_size_t(files_matched);
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
			last_match_count = G.grep_lines.size;
			last_files_matched = files_matched;
			visible_dirty = 0;
			needs_redraw = 0;
		}

		char c;
		confirm_key_ty key = confirm_read_key_timeout(&c, 20);
		if (key == KEY_NONE)
			continue;

		jstr_ty *active_buf = grep_field_buf(find_buf, files_buf, include_buf, exclude_buf, active_field);
		int edit_key = 0;

		switch (key) {
		case KEY_ENTER:
			pending_enter = 1;
			if (phase == GREP_UI_READY && !rescanning && !needs_rescan && end_requested) {
				if (G.grep_lines.size > 0) {
					restore_terminal();
					grep_emit_selected();
					pipeline_ui_ack_send(0);
					return JSTR_RET_SUCC;
				}
				pending_enter = 0;
			}
			break;

		case KEY_ALT_J:
			if (G.total_lines > 0 && G.selected_line + 1 < G.total_lines) {
				G.selected_line++;
				if (G.selected_line >= G.scroll_offset + G.max_preview_lines)
					G.scroll_offset = G.selected_line - G.max_preview_lines + 1;
				needs_redraw = 1;
			}
			break;

		case KEY_CTRL_J:
		case KEY_DOWN:
		case KEY_TAB:
			vim_cancel_pending();
			active_field = (active_field + 1) % GREP_FIELD_COUNT;
			needs_redraw = 1;
			break;

		case KEY_ALT_K:
			if (G.selected_line > 0) {
				G.selected_line--;
				if (G.selected_line < G.scroll_offset)
					G.scroll_offset = G.selected_line;
				needs_redraw = 1;
			}
			break;

		case KEY_CTRL_K:
		case KEY_UP:
		case KEY_SHIFT_TAB:
			vim_cancel_pending();
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
			edit_key = 1;
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
			edit_key = 1;
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
			edit_key = 1;
			if (active_buf) {
				jstr_empty_j(active_buf);
				cursors[active_field] = 0;
				needs_redraw = 1;
				if (grep_field_affects_recompile(active_field))
					needs_rescan = 1;
			}
			break;

		case KEY_CHAR:
			edit_key = 1;
			if (esc_char_pending) {
				esc_char_pending = 0;
				vim_set_insert_mode(0);
			}
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
		if (edit_key && needs_rescan)
			rescan_due = grep_now_ms() + GREP_RESCAN_DEBOUNCE_MS;
	}

	restore_terminal();
	return JSTR_RET_SUCC;
}

/**
 * @brief Run the confirm TUI until selection or quit.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param t compiled fixed-string matcher.
 * @param find_buf FIND field buffer.
 * @param rplc_buf REPLACE field buffer.
 * @param flags_buf parameter defined by the owning module contract.
 * @param files_buf Files substring buffer.
 * @param include_buf include regex buffer.
 * @param exclude_buf exclude regex buffer.
 * @param backup_buf backup suffix buffer.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
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
	G.find_plain.size = 0;
	G.rplc_plain.size = 0;

	for (;;) {
		if (needs_redraw) {
			if (jstr_unlikely(!ui_ok()))
				break;
			jstr_unescape_copy(&G.find_plain, find_buf);
			jstr_unescape_copy(&G.rplc_plain, rplc_buf);
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
				const char *ptn = (G.find_plain.size > 0 && G.find_plain.data) ? G.find_plain.data : "";
				comp_ret = far_compile(t, ptn, G.find_plain.size, G.rplc_plain.data ? G.rplc_plain.data : "", G.rplc_plain.size, 1, err_buf, sizeof(err_buf));
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
					const char *ptn = (G.find_plain.size > 0 && G.find_plain.data) ? G.find_plain.data : "";
					ui_scan_file(t, &file->content, file->fname, file->fname_len, ptn, G.find_plain.size, G.rplc_plain.data ? G.rplc_plain.data : "", G.rplc_plain.size, &file_matches);
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
				(void)jstr_io_fwrite(". (some previews omitted)", 1, S_LEN(". (some previews omitted)"), stdout);
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

		case KEY_ALT_J:
			if (G.total_lines > 0 && G.selected_line + 1 < G.total_lines) {
				G.selected_line++;
				if (G.selected_line >= G.scroll_offset + G.max_preview_lines)
					G.scroll_offset = G.selected_line - G.max_preview_lines + 1;
				needs_redraw = 1;
			}
			break;

		case KEY_CTRL_J:
		case KEY_DOWN:
		case KEY_TAB:
			vim_cancel_pending();
			active_field = (active_field + 1) % FIELD_COUNT;
			needs_redraw = 1;
			break;

		case KEY_ALT_K:
			if (G.selected_line > 0) {
				G.selected_line--;
				if (G.selected_line < G.scroll_offset)
					G.scroll_offset = G.selected_line;
				needs_redraw = 1;
			}
			break;

		case KEY_CTRL_K:
		case KEY_UP:
		case KEY_SHIFT_TAB:
			vim_cancel_pending();
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
			if (esc_char_pending) {
				esc_char_pending = 0;
				vim_set_insert_mode(0);
			}
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
	return JSTR_RET_SUCC;
}


/**
 * @brief Report whether terminal raw mode is active.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Nonzero when the condition holds; zero otherwise.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
int
terminal_active(void)
{
	return term_state == TERM_RAW;
}

/**
 * @brief Return the cached terminal column count.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
unsigned short
terminal_cols(void)
{
	return get_terminal_cols();
}

/**
 * @brief Return the cached terminal row count.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
unsigned short
terminal_rows(void)
{
	return get_terminal_rows();
}

/**
 * @brief Cancel and wait for a stale live-grep root.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param root per-root pipeline context.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
ui_drain_root(root_ctx_ty *R root)
{
	if (root != NULL) {
		atomic_store_explicit(&root->cancel, true, memory_order_release);
		while (atomic_load_explicit(&root->workers_done, memory_order_acquire) <
		       pipeline_worker_count()) {
			struct timespec ts = { 0, 1000000 };
			nanosleep(&ts, NULL);
		}
	}
	for (size_t w = 0; w < pipeline_worker_count(); ++w) {
		far_result_ty *res;
		while ((res = pipeline_done_try_recv(w)) != NULL)
			ui_result_free(res);
	}
}

/**
 * @brief Dedicated Stage-C UI thread.
 *
 * @details This function is part of the terminal.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param arg parameter defined by the owning module contract.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
far_thread_ret_ty
terminal_ui_thread(void *arg)
{
	(void)arg;
	int ui_quit = 0;
	ui_stop_requested = 0;
	for (;;) {
		far_ui_cmd_ty *const cmd = pipeline_ui_cmd_recv();
		if (cmd == NULL || cmd->kind == FAR_UI_STOP)
			break;
		if (cmd->kind == FAR_UI_END) {
			pipeline_ui_ack_send(0);
			if (ui_quit)
				break;
			continue;
		}
		root_ctx_ty *const root = cmd->root;
		if (ui_quit) {
			ui_drain_root(root);
			pipeline_ui_ack_send(0);
			continue;
		}
		jstr_empty_j(&G.interactive_find_buf);
		jstr_empty_j(&G.interactive_files_buf);
		jstr_empty_j(&G.interactive_include_buf);
		jstr_empty_j(&G.interactive_exclude_buf);
		if (root->a->find_len > 0)
			DIE_IF(jstr_chk(jstr_append_len_j(&G.interactive_find_buf, root->a->find, root->a->find_len)), "%s", "Out of memory.\n");
		if (G.include_pat)
			DIE_IF(jstr_chk(jstr_append_len_j(&G.interactive_include_buf, G.include_pat, strlen(G.include_pat))), "%s", "Out of memory.\n");
		if (G.exclude_pat)
			DIE_IF(jstr_chk(jstr_append_len_j(&G.interactive_exclude_buf, G.exclude_pat, strlen(G.exclude_pat))), "%s", "Out of memory.\n");
		grep_interactive_loop(root->t, &G.interactive_find_buf, &G.interactive_files_buf, &G.interactive_include_buf, &G.interactive_exclude_buf, root);
		if (ui_stop_requested)
			break;
		ui_quit = 1;
	}
	return FAR_THREAD_RETURN;
}
