/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef SPMC_H
#define SPMC_H

#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct spmc_slot_ty {
	alignas(64) atomic_size_t seq;
	void *v;
} spmc_slot_ty;

typedef struct spmc_chan_ty {
	spmc_slot_ty *slots;
	size_t cap;
	size_t mask;
	size_t tail;
	atomic_bool closed;
	alignas(64) atomic_size_t head;
} spmc_chan_ty;

/**
 * @brief Initialize a caller-owned bounded SPMC channel.
 *
 * @details Contract for the public declaration in spmc.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @param slots caller-provided backing slot array.
 * @param cap power-of-two capacity.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage A produces; B workers consume.
 */
int spmc_chan_init(spmc_chan_ty *c, spmc_slot_ty *slots, size_t cap);
/**
 * @brief Publish one item from the single producer to any consumer.
 *
 * @details Contract for the public declaration in spmc.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @param v opaque value published into the queue.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage A produces; B workers consume.
 */
int spmc_chan_send(spmc_chan_ty *c, void *v);
/**
 * @brief Claim the next available item, blocking while empty.
 *
 * @details Contract for the public declaration in spmc.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage A produces; B workers consume.
 */
void *spmc_chan_recv(spmc_chan_ty *c);
/**
 * @brief Attempt to claim the next available item without blocking.
 *
 * @details Contract for the public declaration in spmc.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage A produces; B workers consume.
 */
void *spmc_chan_try_recv(spmc_chan_ty *c);
/**
 * @brief Close an SPMC channel.
 *
 * @details Contract for the public declaration in spmc.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage A produces; B workers consume.
 */
void spmc_chan_close(spmc_chan_ty *c);
/**
 * @brief Report whether an SPMC channel is closed.
 *
 * @details Contract for the public declaration in spmc.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage A produces; B workers consume.
 */
int spmc_chan_is_closed(spmc_chan_ty *c);

#endif /* SPMC_H */
