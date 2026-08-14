/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef VIM_H
#define VIM_H

#include "common.h"

int vim_is_insert_mode(void);
void vim_set_insert_mode(int mode);
int vim_handle_key(char c, jstr_ty *active_buf, size_t *cursors, int *active_field, int *needs_redraw, int *needs_recompile);

#endif /* VIM_H */
