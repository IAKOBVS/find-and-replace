/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef TRAVERSE_H
#define TRAVERSE_H

#include "stage.h"
#include "thread_compat.h"

far_thread_ret_ty traverse_thread(void *arg);

JSTR_IO_FTW_FUNC_MATCH(matcher, fname, fname_len, args);

#endif /* TRAVERSE_H */
