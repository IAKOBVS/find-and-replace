/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef GREP_WORKER_H
#define GREP_WORKER_H

#include "stage.h"
#include "thread_compat.h"

/**
 * @brief Stage-D scan/cache loop.
 *
 * @details Contract for the public declaration in grep_worker.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param arg parameter defined by the owning contract.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage D or caller named by the API.
 */
far_thread_ret_ty grep_worker_thread(void *arg);

#endif /* GREP_WORKER_H */
