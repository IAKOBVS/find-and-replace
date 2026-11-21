/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef PROCFS_H
#define PROCFS_H

#include <stddef.h>
#include <string.h>

struct procfs_iter {
	const char *pos;
	const char *end;
};

/**
 * @brief Open /proc/meminfo and initialize an iterator.
 *
 * @details Contract for the public declaration in procfs.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param iter parameter defined by the owning contract.
 * @param buf growable byte buffer.
 * @param len valid byte count.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Owning stage.
 */
void
procfs_iter_init(struct procfs_iter *iter, const char *buf, unsigned int len);

/**
 * @brief Read the next line from an open procfs iterator.
 *
 * @details Contract for the public declaration in procfs.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param iter parameter defined by the owning contract.
 * @param key decoded input key.
 * @param key_len parameter defined by the owning contract.
 * @param val value to format.
 * @param val_len parameter defined by the owning contract.
 * @param delimiter parameter defined by the owning contract.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Owning stage.
 */
int
procfs_iter_next(struct procfs_iter *iter, const char **key, unsigned int *key_len, const char **val, unsigned int *val_len, int delimiter);

/**
 * @brief Return MemAvailable in bytes with a documented fallback.
 *
 * @details Contract for the public declaration in procfs.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Owning stage.
 */
size_t
procfs_mem_available(void);

#endif /* PROCFS_H */
