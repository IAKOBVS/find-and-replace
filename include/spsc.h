/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef SPSC_H
#define SPSC_H

#include <stdatomic.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct spsc_chan_ty {
	void **slots;
	size_t cap;
	size_t mask;
	atomic_bool closed;
	int owned;
	alignas(64) atomic_size_t head;
	alignas(64) atomic_size_t tail;
} spsc_chan_ty;

/**
 * @brief Initialize a caller-owned bounded SPSC channel.
 *
 * @details Contract for the public declaration in spsc.h. It reads only
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
 *   Any thread; single-producer/single-consumer discipline.
 */
int spsc_chan_init(spsc_chan_ty *c, void **slots, size_t cap);
/**
 * @brief Apply bounded exponential backoff for channel waits.
 *
 * @details Contract for the public declaration in spsc.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param spin parameter defined by the owning contract.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Any thread; single-producer/single-consumer discipline.
 */
void spsc_backoff(unsigned int *spin);
/**
 * @brief Allocate a bounded SPSC channel with caller-independent storage.
 *
 * @details Contract for the public declaration in spsc.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param cap power-of-two capacity.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Any thread; single-producer/single-consumer discipline.
 */
spsc_chan_ty *spsc_chan_new(size_t cap);
/**
 * @brief Release a heap-owned SPSC channel.
 *
 * @details Contract for the public declaration in spsc.h. It reads only
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
 *   Any thread; single-producer/single-consumer discipline.
 */
void spsc_chan_free(spsc_chan_ty *c);
/**
 * @brief Publish one item to a bounded SPSC channel, blocking while full.
 *
 * @details Contract for the public declaration in spsc.h. It reads only
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
 *   Any thread; single-producer/single-consumer discipline.
 */
int spsc_chan_send(spsc_chan_ty *c, void *v);
/**
 * @brief Attempt to publish one item without blocking.
 *
 * @details Contract for the public declaration in spsc.h. It reads only
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
 *   Any thread; single-producer/single-consumer discipline.
 */
int spsc_chan_try_send(spsc_chan_ty *c, void *v);
/**
 * @brief Consume the next item from a bounded SPSC channel.
 *
 * @details Contract for the public declaration in spsc.h. It reads only
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
 *   Any thread; single-producer/single-consumer discipline.
 */
void *spsc_chan_recv(spsc_chan_ty *c);
/**
 * @brief Attempt to consume the next item without blocking.
 *
 * @details Contract for the public declaration in spsc.h. It reads only
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
 *   Any thread; single-producer/single-consumer discipline.
 */
void *spsc_chan_try_recv(spsc_chan_ty *c);
/**
 * @brief Close an SPSC channel and wake blocked peers.
 *
 * @details Contract for the public declaration in spsc.h. It reads only
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
 *   Any thread; single-producer/single-consumer discipline.
 */
void spsc_chan_close(spsc_chan_ty *c);
/**
 * @brief Report whether an SPSC channel is closed.
 *
 * @details Contract for the public declaration in spsc.h. It reads only
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
 *   Any thread; single-producer/single-consumer discipline.
 */
int spsc_chan_is_closed(spsc_chan_ty *c);

#endif /* SPSC_H */
