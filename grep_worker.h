/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef GREP_WORKER_H
#define GREP_WORKER_H

#include "stage.h"
#include "thread_compat.h"

far_thread_ret_ty grep_worker_thread(void *arg);

#endif /* GREP_WORKER_H */
