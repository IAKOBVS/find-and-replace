/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "spsc.h"

#include <sched.h>
#include <stdlib.h>
#include <time.h>

#define SPSC_YIELD_SPIN 64
#define SPSC_SLEEP_NS   100000

/**
 * @brief Apply bounded exponential backoff for channel waits.
 *
 * @details This function is part of the spsc.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param spin parameter defined by the owning module contract.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any thread; each channel enforces the single-producer/single-consumer discipline.
 */
void
spsc_backoff(unsigned int *spin)
{
	if (*spin >= SPSC_YIELD_SPIN * 4) {
		struct timespec ts;
		ts.tv_sec = 0;
		ts.tv_nsec = SPSC_SLEEP_NS;
		nanosleep(&ts, NULL);
	} else if (*spin >= SPSC_YIELD_SPIN) {
		sched_yield();
	}
	++*spin;
}

/**
 * @brief Initialize a caller-owned bounded SPSC channel.
 *
 * @details This function is part of the spsc.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @param slots caller-provided backing slot array.
 * @param cap power-of-two capacity.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any thread; each channel enforces the single-producer/single-consumer discipline.
 */
int
spsc_chan_init(spsc_chan_ty *c, void **slots, size_t cap)
{
	if (c == NULL || slots == NULL || cap < 2 || (cap & (cap - 1)) != 0)
		return -1;
	c->slots = slots;
	c->cap = cap;
	c->mask = cap - 1;
	c->owned = 0;
	atomic_init(&c->head, 0);
	atomic_init(&c->tail, 0);
	atomic_init(&c->closed, false);
	return 0;
}

/**
 * @brief Allocate a bounded SPSC channel with caller-independent storage.
 *
 * @details This function is part of the spsc.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param cap power-of-two capacity.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any thread; each channel enforces the single-producer/single-consumer discipline.
 */
spsc_chan_ty *
spsc_chan_new(size_t cap)
{
	size_t n = 2;
	while (n < cap) {
		if (n > (size_t)-1 / 2)
			return NULL;
		n <<= 1;
	}
	if (n > (size_t)-1 / sizeof(void *))
		return NULL;
	spsc_chan_ty *c = malloc(sizeof *c);
	if (c == NULL)
		return NULL;
	void **slots = calloc(n, sizeof *slots);
	if (slots == NULL)
		goto err;
	if (spsc_chan_init(c, slots, n) != 0)
		goto err;
	c->owned = 1;
	return c;
err:
	free(slots);
	free(c);
	return NULL;
}

/**
 * @brief Release a heap-owned SPSC channel.
 *
 * @details This function is part of the spsc.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any thread; each channel enforces the single-producer/single-consumer discipline.
 */
void
spsc_chan_free(spsc_chan_ty *c)
{
	if (c == NULL)
		return;
	if (c->owned)
		free(c->slots);
	free(c);
}

/**
 * @brief Publish one item to a bounded SPSC channel, blocking while full.
 *
 * @details This function is part of the spsc.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @param v opaque value published into the queue.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any thread; each channel enforces the single-producer/single-consumer discipline.
 */
int
spsc_chan_send(spsc_chan_ty *c, void *v)
{
	unsigned int spin = 0;
	size_t tail = atomic_load_explicit(&c->tail, memory_order_relaxed);
	for (;;) {
		if (atomic_load_explicit(&c->closed, memory_order_acquire))
			return -1;
		const size_t head = atomic_load_explicit(&c->head, memory_order_acquire);
		if (tail - head < c->cap) {
			c->slots[tail & c->mask] = v;
			atomic_store_explicit(&c->tail, tail + 1, memory_order_release);
			return 0;
		}
		spsc_backoff(&spin);
	}
}

/**
 * @brief Attempt to publish one item without blocking.
 *
 * @details This function is part of the spsc.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @param v opaque value published into the queue.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any thread; each channel enforces the single-producer/single-consumer discipline.
 */
int
spsc_chan_try_send(spsc_chan_ty *c, void *v)
{
	if (atomic_load_explicit(&c->closed, memory_order_acquire))
		return -1;
	const size_t tail = atomic_load_explicit(&c->tail, memory_order_relaxed);
	const size_t head = atomic_load_explicit(&c->head, memory_order_acquire);
	if (tail - head >= c->cap)
		return -1;
	c->slots[tail & c->mask] = v;
	atomic_store_explicit(&c->tail, tail + 1, memory_order_release);
	return 0;
}

/**
 * @brief Consume the next item from a bounded SPSC channel.
 *
 * @details This function is part of the spsc.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any thread; each channel enforces the single-producer/single-consumer discipline.
 */
void *
spsc_chan_recv(spsc_chan_ty *c)
{
	unsigned int spin = 0;
	size_t head = atomic_load_explicit(&c->head, memory_order_relaxed);
	for (;;) {
		const size_t tail = atomic_load_explicit(&c->tail, memory_order_acquire);
		if (head != tail) {
			void *v = c->slots[head & c->mask];
			atomic_store_explicit(&c->head, head + 1, memory_order_release);
			return v;
		}
		if (atomic_load_explicit(&c->closed, memory_order_acquire))
			return NULL;
		spsc_backoff(&spin);
	}
}

/**
 * @brief Attempt to consume the next item without blocking.
 *
 * @details This function is part of the spsc.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any thread; each channel enforces the single-producer/single-consumer discipline.
 */
void *
spsc_chan_try_recv(spsc_chan_ty *c)
{
	const size_t head = atomic_load_explicit(&c->head, memory_order_relaxed);
	const size_t tail = atomic_load_explicit(&c->tail, memory_order_acquire);
	if (head == tail)
		return NULL;
	void *v = c->slots[head & c->mask];
	atomic_store_explicit(&c->head, head + 1, memory_order_release);
	return v;
}

/**
 * @brief Close an SPSC channel and wake blocked peers.
 *
 * @details This function is part of the spsc.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any thread; each channel enforces the single-producer/single-consumer discipline.
 */
void
spsc_chan_close(spsc_chan_ty *c)
{
	atomic_store_explicit(&c->closed, true, memory_order_release);
}

/**
 * @brief Report whether an SPSC channel is closed.
 *
 * @details This function is part of the spsc.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any thread; each channel enforces the single-producer/single-consumer discipline.
 */
int
spsc_chan_is_closed(spsc_chan_ty *c)
{
	return atomic_load_explicit(&c->closed, memory_order_acquire);
}
