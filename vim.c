/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "vim.h"
#include <ctype.h>

static int insert_mode = 1;

int
vim_is_insert_mode(void)
{
	return insert_mode;
}

void
vim_set_insert_mode(int mode)
{
	insert_mode = mode;
}

int
vim_handle_key(char c, jstr_ty *active_buf, size_t *cursors, int *active_field, int *needs_redraw, int *needs_recompile)
{
	if (insert_mode) {
		return 0;
	}

	switch (c) {
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
	case 'h':
		if (cursors[*active_field] > 0) {
			cursors[*active_field]--;
			*needs_redraw = 1;
		}
		break;
	case 'l':
		if (active_buf && cursors[*active_field] < active_buf->size) {
			cursors[*active_field]++;
			*needs_redraw = 1;
		}
		break;
	case 'j':
		*active_field = (*active_field + 1) % 4;
		*needs_redraw = 1;
		break;
	case 'k':
		*active_field = (*active_field + 3) % 4;
		*needs_redraw = 1;
		break;
	case '0':
		cursors[*active_field] = 0;
		*needs_redraw = 1;
		break;
	case '$':
		if (active_buf) {
			cursors[*active_field] = active_buf->size;
		}
		*needs_redraw = 1;
		break;
	case 'x':
		if (active_buf && cursors[*active_field] < active_buf->size) {
			memmove(active_buf->data + cursors[*active_field],
			        active_buf->data + cursors[*active_field] + 1,
			        active_buf->size - cursors[*active_field] - 1);
			active_buf->size--;
			active_buf->data[active_buf->size] = '\0';
			*needs_redraw = 1;
			*needs_recompile = 1;
		}
		break;
	case 'w':
		if (active_buf && cursors[*active_field] < active_buf->size) {
			size_t pos = cursors[*active_field];
			if (isalnum((unsigned char)active_buf->data[pos])) {
				while (pos < active_buf->size && isalnum((unsigned char)active_buf->data[pos])) {
					pos++;
				}
			} else {
				while (pos < active_buf->size && !isalnum((unsigned char)active_buf->data[pos]) && !isspace((unsigned char)active_buf->data[pos])) {
					pos++;
				}
			}
			while (pos < active_buf->size && isspace((unsigned char)active_buf->data[pos])) {
				pos++;
			}
			cursors[*active_field] = pos;
			*needs_redraw = 1;
		}
		break;
	case 'b':
		if (active_buf && cursors[*active_field] > 0) {
			size_t pos = cursors[*active_field];
			if (pos > 0) {
				pos--;
			}
			while (pos > 0 && isspace((unsigned char)active_buf->data[pos])) {
				pos--;
			}
			if (isalnum((unsigned char)active_buf->data[pos])) {
				while (pos > 0 && isalnum((unsigned char)active_buf->data[pos - 1])) {
					pos--;
				}
			} else {
				while (pos > 0 && !isalnum((unsigned char)active_buf->data[pos - 1]) && !isspace((unsigned char)active_buf->data[pos - 1])) {
					pos--;
				}
			}
			cursors[*active_field] = pos;
			*needs_redraw = 1;
		}
		break;
	default:
		break;
	}

	return 1;
}
