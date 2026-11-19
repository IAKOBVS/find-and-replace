/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "vim.h"
#include <ctype.h>

/* vim-mode editor state shared across the interactive TUI: whether we are
 * typing (insert) or navigating (normal), and the pending operator ('d' or
 * 'c') waiting for a motion key when in normal mode. */
static vim_state_ty vim_st = VIM_INSERT;

/**
 * @brief Return the current line-editor mode.
 *
 * @details This function is part of the vim.c contract. It reads only
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
int
vim_is_insert_mode(void)
{
	return vim_st == VIM_INSERT;
}

vim_state_ty
vim_state(void)
{
	return vim_st;
}

void
vim_set_state(vim_state_ty state)
{
	vim_st = state;
}

/**
 * @brief Set the line-editor mode and clear any pending operator.
 *
 * @details This function is part of the vim.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param mode new editor mode.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
void
vim_set_insert_mode(int mode)
{
	vim_st = mode ? VIM_INSERT : VIM_NORMAL;
}

void
vim_cancel_pending(void)
{
	if (vim_st == VIM_OP_D || vim_st == VIM_OP_C)
		vim_st = VIM_NORMAL;
}

/**
 * @brief Compute the next word boundary in an editable buffer.
 *
 * @details This function is part of the vim.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param buf growable byte buffer.
 * @param pos parameter defined by the owning module contract.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static size_t
get_word_forward(const jstr_ty *buf, size_t pos)
{
	/* vim 'w' motion: from an alnum run, skip to its end; from a punctuation
	 * run, skip to its end; then skip trailing whitespace. */
	if (!buf || pos >= buf->size)
		return buf ? buf->size : 0;
	if (isalnum((unsigned char)buf->data[pos])) {
		while (pos < buf->size && isalnum((unsigned char)buf->data[pos]))
			pos++;
	} else {
		while (pos < buf->size && !isalnum((unsigned char)buf->data[pos]) && !isspace((unsigned char)buf->data[pos]))
			pos++;
	}
	while (pos < buf->size && isspace((unsigned char)buf->data[pos]))
		pos++;
	return pos;
}

/**
 * @brief Compute the previous word boundary in an editable buffer.
 *
 * @details This function is part of the vim.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param buf growable byte buffer.
 * @param pos parameter defined by the owning module contract.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static size_t
get_word_backward(const jstr_ty *buf, size_t pos)
{
	/* vim 'b' motion: walk back past trailing whitespace, then to the start
	 * of the alnum (or punctuation) run that precedes the cursor. */
	if (!buf || pos == 0)
		return 0;
	pos--;
	while (pos > 0 && isspace((unsigned char)buf->data[pos]))
		pos--;
	if (isalnum((unsigned char)buf->data[pos])) {
		while (pos > 0 && isalnum((unsigned char)buf->data[pos - 1]))
			pos--;
	} else {
		while (pos > 0 && !isalnum((unsigned char)buf->data[pos - 1]) && !isspace((unsigned char)buf->data[pos - 1]))
			pos--;
	}
	return pos;
}

/**
 * @brief Delete a half-open byte range from an editable buffer.
 *
 * @details This function is part of the vim.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param buf growable byte buffer.
 * @param start inclusive start offset.
 * @param end exclusive end offset.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
static void
delete_range(jstr_ty *buf, size_t start, size_t end)
{
	/* In-buffer deletion: shift the tail down over the removed range and keep
	 * the buffer NUL-terminated. */
	if (!buf || start >= end || start >= buf->size)
		return;
	if (end > buf->size)
		end = buf->size;
	memmove(buf->data + start, buf->data + end, buf->size - end);
	buf->size -= (end - start);
	buf->data[buf->size] = '\0';
}

/**
 * @brief Apply a vim normal-mode key to the active field.
 *
 * @details This function is part of the vim.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @param active_buf parameter defined by the owning module contract.
 * @param cursors per-field cursor array.
 * @param active_field zero-based active field index.
 * @param needs_redraw parameter defined by the owning module contract.
 * @param needs_recompile parameter defined by the owning module contract.
 * @param field_count number of fields.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage C only.
 */
int
vim_handle_key(char c, jstr_ty *active_buf, size_t *cursors, size_t *active_field, int *needs_redraw, int *needs_recompile, size_t field_count)
{
	if (vim_st == VIM_INSERT) {
		/* Typing is handled by the caller (insert the char into active_buf);
		 * only normal-mode navigation lands here. */
		return 0;
	}

	if (vim_st == VIM_OP_D || vim_st == VIM_OP_C) {
		/* An operator is pending: the next key is its motion, or the key itself
		 * for a doubled operator like dd/cc. 'c' switches to insert mode. */
		vim_state_ty op = vim_st;
		vim_st = VIM_NORMAL;

		if (op == VIM_OP_D) {
			if (c == 'd') {
				if (active_buf) {
					jstr_empty_j(active_buf);
					cursors[*active_field] = 0;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			} else if (c == 'w') {
				if (active_buf) {
					size_t end_pos = get_word_forward(active_buf, cursors[*active_field]);
					delete_range(active_buf, cursors[*active_field], end_pos);
					if (cursors[*active_field] >= active_buf->size && active_buf->size > 0)
						cursors[*active_field] = active_buf->size - 1;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			} else if (c == 'b') {
				if (active_buf) {
					size_t start_pos = get_word_backward(active_buf, cursors[*active_field]);
					delete_range(active_buf, start_pos, cursors[*active_field]);
					cursors[*active_field] = start_pos;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			} else if (c == '0') {
				if (active_buf) {
					delete_range(active_buf, 0, cursors[*active_field]);
					cursors[*active_field] = 0;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			} else if (c == '$') {
				if (active_buf) {
					delete_range(active_buf, cursors[*active_field], active_buf->size);
					if (cursors[*active_field] >= active_buf->size && active_buf->size > 0)
						cursors[*active_field] = active_buf->size - 1;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			}
		} else if (op == VIM_OP_C) {
			if (c == 'c') {
				if (active_buf) {
					jstr_empty_j(active_buf);
					cursors[*active_field] = 0;
					vim_st = VIM_INSERT;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			} else if (c == 'w') {
				if (active_buf) {
					size_t end_pos = get_word_forward(active_buf, cursors[*active_field]);
					delete_range(active_buf, cursors[*active_field], end_pos);
					vim_st = VIM_INSERT;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			} else if (c == 'b') {
				if (active_buf) {
					size_t start_pos = get_word_backward(active_buf, cursors[*active_field]);
					delete_range(active_buf, start_pos, cursors[*active_field]);
					cursors[*active_field] = start_pos;
					vim_st = VIM_INSERT;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			} else if (c == '0') {
				if (active_buf) {
					delete_range(active_buf, 0, cursors[*active_field]);
					cursors[*active_field] = 0;
					vim_st = VIM_INSERT;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			} else if (c == '$') {
				if (active_buf) {
					delete_range(active_buf, cursors[*active_field], active_buf->size);
					vim_st = VIM_INSERT;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			}
		}
	}

	switch (c) {
	/* Insert-mode entry keys: i = here, a = after, I = line start, A = line end. */
	case 'i':
		vim_st = VIM_INSERT;
		*needs_redraw = 1;
		break;
	case 'a':
		vim_st = VIM_INSERT;
		if (active_buf && cursors[*active_field] < active_buf->size)
			cursors[*active_field]++;
		*needs_redraw = 1;
		break;
	case 'I':
		vim_st = VIM_INSERT;
		cursors[*active_field] = 0;
		*needs_redraw = 1;
		break;
	case 'A':
		vim_st = VIM_INSERT;
		if (active_buf)
			cursors[*active_field] = active_buf->size;
		*needs_redraw = 1;
		break;
	case 'd':
		vim_st = VIM_OP_D;
		break;
	case 'D':
		if (active_buf) {
			delete_range(active_buf, cursors[*active_field], active_buf->size);
			if (cursors[*active_field] >= active_buf->size && active_buf->size > 0)
				cursors[*active_field] = active_buf->size - 1;
			*needs_redraw = 1;
			*needs_recompile = 1;
		}
		break;
	case 'c':
		vim_st = VIM_OP_C;
		break;
	case 'C':
		if (active_buf) {
			delete_range(active_buf, cursors[*active_field], active_buf->size);
			vim_st = VIM_INSERT;
			*needs_redraw = 1;
			*needs_recompile = 1;
		}
		break;
	case 'h':
		if (cursors[*active_field] > 0) {
			cursors[*active_field]--;
			*needs_redraw = 1;
		}
		break;
	case 'l':
		if (active_buf && active_buf->size > 0) {
			if (cursors[*active_field] < active_buf->size - 1) {
				cursors[*active_field]++;
				*needs_redraw = 1;
			}
		}
		break;
	case 'j':
		/* Move down/up between TUI fields, wrapping at either edge. */
		vim_cancel_pending();
		*active_field = (*active_field + 1) % field_count;
		*needs_redraw = 1;
		break;
	case 'k':
		vim_cancel_pending();
		*active_field = (*active_field + field_count - 1) % field_count;
		*needs_redraw = 1;
		break;
	case '0':
		cursors[*active_field] = 0;
		*needs_redraw = 1;
		break;
	case '$':
		if (active_buf)
			cursors[*active_field] = (active_buf->size > 0) ? active_buf->size - 1 : 0;
		*needs_redraw = 1;
		break;
	case 'x':
		if (active_buf && active_buf->size > 0) {
			if (cursors[*active_field] >= active_buf->size)
				cursors[*active_field] = active_buf->size - 1;
			delete_range(active_buf, cursors[*active_field], cursors[*active_field] + 1);
			if (cursors[*active_field] >= active_buf->size && active_buf->size > 0)
				cursors[*active_field] = active_buf->size - 1;
			*needs_redraw = 1;
			*needs_recompile = 1;
		}
		break;
	case 'X':
		if (active_buf && cursors[*active_field] > 0) {
			delete_range(active_buf, cursors[*active_field] - 1, cursors[*active_field]);
			cursors[*active_field]--;
			*needs_redraw = 1;
			*needs_recompile = 1;
		}
		break;
	case 'w':
		if (active_buf) {
			cursors[*active_field] = get_word_forward(active_buf, cursors[*active_field]);
			if (cursors[*active_field] >= active_buf->size && active_buf->size > 0)
				cursors[*active_field] = active_buf->size - 1;
			*needs_redraw = 1;
		}
		break;
	case 'b':
		if (active_buf) {
			cursors[*active_field] = get_word_backward(active_buf, cursors[*active_field]);
			*needs_redraw = 1;
		}
		break;
	default:
		break;
	}

	return 1;
}
