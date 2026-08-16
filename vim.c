/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "vim.h"
#include <ctype.h>

/* vim-mode editor state shared across the interactive TUI: whether we are
 * typing (insert) or navigating (normal), and the pending operator ('d' or
 * 'c') waiting for a motion key when in normal mode. */
static int insert_mode = 1;
static char pending_op = 0;

int
vim_is_insert_mode(void)
{
	return insert_mode;
}

void
vim_set_insert_mode(int mode)
{
	insert_mode = mode;
	pending_op = 0;
}

static size_t
get_word_forward(const jstr_ty *buf, size_t pos)
{
	/* vim 'w' motion: from an alnum run, skip to its end; from a punctuation
	 * run, skip to its end; then skip trailing whitespace. */
	if (!buf || pos >= buf->size) {
		return buf ? buf->size : 0;
	}
	if (isalnum((unsigned char)buf->data[pos])) {
		while (pos < buf->size && isalnum((unsigned char)buf->data[pos])) {
			pos++;
		}
	} else {
		while (pos < buf->size && !isalnum((unsigned char)buf->data[pos]) && !isspace((unsigned char)buf->data[pos])) {
			pos++;
		}
	}
	while (pos < buf->size && isspace((unsigned char)buf->data[pos])) {
		pos++;
	}
	return pos;
}

static size_t
get_word_backward(const jstr_ty *buf, size_t pos)
{
	/* vim 'b' motion: walk back past trailing whitespace, then to the start
	 * of the alnum (or punctuation) run that precedes the cursor. */
	if (!buf || pos == 0) {
		return 0;
	}
	pos--;
	while (pos > 0 && isspace((unsigned char)buf->data[pos])) {
		pos--;
	}
	if (isalnum((unsigned char)buf->data[pos])) {
		while (pos > 0 && isalnum((unsigned char)buf->data[pos - 1])) {
			pos--;
		}
	} else {
		while (pos > 0 && !isalnum((unsigned char)buf->data[pos - 1]) && !isspace((unsigned char)buf->data[pos - 1])) {
			pos--;
		}
	}
	return pos;
}

static void
delete_range(jstr_ty *buf, size_t start, size_t end)
{
	/* In-buffer deletion: shift the tail down over the removed range and keep
	 * the buffer NUL-terminated. */
	if (!buf || start >= end || start >= buf->size) {
		return;
	}
	if (end > buf->size) {
		end = buf->size;
	}
	memmove(buf->data + start, buf->data + end, buf->size - end);
	buf->size -= (end - start);
	buf->data[buf->size] = '\0';
}

int
vim_handle_key(char c, jstr_ty *active_buf, size_t *cursors, size_t *active_field, int *needs_redraw, int *needs_recompile, size_t field_count)
{
	if (insert_mode) {
		/* Typing is handled by the caller (insert the char into active_buf);
		 * only normal-mode navigation lands here. */
		return 0;
	}

	if (pending_op) {
		/* An operator ('d'/'c') is pending: the next key is its motion, or the
		 * key itself for a doubled operator like dd/cc. 'c' also switches back
		 * to insert mode (like vim's c = delete + insert). */
		char op = pending_op;
		pending_op = 0;

		if (op == 'd') {
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
					if (cursors[*active_field] >= active_buf->size && active_buf->size > 0) {
						cursors[*active_field] = active_buf->size - 1;
					}
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
					if (cursors[*active_field] >= active_buf->size && active_buf->size > 0) {
						cursors[*active_field] = active_buf->size - 1;
					}
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			}
		} else if (op == 'c') {
			if (c == 'c') {
				if (active_buf) {
					jstr_empty_j(active_buf);
					cursors[*active_field] = 0;
					insert_mode = 1;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			} else if (c == 'w') {
				if (active_buf) {
					size_t end_pos = get_word_forward(active_buf, cursors[*active_field]);
					delete_range(active_buf, cursors[*active_field], end_pos);
					insert_mode = 1;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			} else if (c == 'b') {
				if (active_buf) {
					size_t start_pos = get_word_backward(active_buf, cursors[*active_field]);
					delete_range(active_buf, start_pos, cursors[*active_field]);
					cursors[*active_field] = start_pos;
					insert_mode = 1;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			} else if (c == '0') {
				if (active_buf) {
					delete_range(active_buf, 0, cursors[*active_field]);
					cursors[*active_field] = 0;
					insert_mode = 1;
					*needs_redraw = 1;
					*needs_recompile = 1;
				}
				return 1;
			} else if (c == '$') {
				if (active_buf) {
					delete_range(active_buf, cursors[*active_field], active_buf->size);
					insert_mode = 1;
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
		insert_mode = 1;
		*needs_redraw = 1;
		break;
	case 'a':
		insert_mode = 1;
		if (active_buf && cursors[*active_field] < active_buf->size) {
			cursors[*active_field]++;
		}
		*needs_redraw = 1;
		break;
	case 'I':
		insert_mode = 1;
		cursors[*active_field] = 0;
		*needs_redraw = 1;
		break;
	case 'A':
		insert_mode = 1;
		if (active_buf) {
			cursors[*active_field] = active_buf->size;
		}
		*needs_redraw = 1;
		break;
	case 'd':
		pending_op = 'd';
		break;
	case 'D':
		if (active_buf) {
			delete_range(active_buf, cursors[*active_field], active_buf->size);
			if (cursors[*active_field] >= active_buf->size && active_buf->size > 0) {
				cursors[*active_field] = active_buf->size - 1;
			}
			*needs_redraw = 1;
			*needs_recompile = 1;
		}
		break;
	case 'c':
		pending_op = 'c';
		break;
	case 'C':
		if (active_buf) {
			delete_range(active_buf, cursors[*active_field], active_buf->size);
			insert_mode = 1;
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
		*active_field = (*active_field + 1) % field_count;
		*needs_redraw = 1;
		break;
	case 'k':
		*active_field = (*active_field + field_count - 1) % field_count;
		*needs_redraw = 1;
		break;
	case '0':
		cursors[*active_field] = 0;
		*needs_redraw = 1;
		break;
	case '$':
		if (active_buf) {
			cursors[*active_field] = (active_buf->size > 0) ? active_buf->size - 1 : 0;
		}
		*needs_redraw = 1;
		break;
	case 'x':
		if (active_buf && active_buf->size > 0) {
			if (cursors[*active_field] >= active_buf->size) {
				cursors[*active_field] = active_buf->size - 1;
			}
			delete_range(active_buf, cursors[*active_field], cursors[*active_field] + 1);
			if (cursors[*active_field] >= active_buf->size && active_buf->size > 0) {
				cursors[*active_field] = active_buf->size - 1;
			}
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
			if (cursors[*active_field] >= active_buf->size && active_buf->size > 0) {
				cursors[*active_field] = active_buf->size - 1;
			}
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
