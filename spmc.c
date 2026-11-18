/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "spmc.h"
#include "spsc.h"

int
spmc_chan_init(spmc_chan_ty *c, spmc_slot_ty *slots, size_t cap)
{
	if (c == NULL || slots == NULL || cap < 2 || (cap & (cap - 1)) != 0)
		return -1;
	c->slots = slots;
	c->cap = cap;
	c->mask = cap - 1;
	c->tail = 0;
	for (size_t i = 0; i < cap; ++i)
		atomic_init(&slots[i].seq, i);
	atomic_init(&c->head, 0);
	atomic_init(&c->closed, false);
	return 0;
}

int
spmc_chan_send(spmc_chan_ty *c, void *v)
{
	unsigned int spin = 0;
	for (;;) {
		if (atomic_load_explicit(&c->closed, memory_order_acquire))
			return -1;
		spmc_slot_ty *const slot = &c->slots[c->tail & c->mask];
		const size_t seq = atomic_load_explicit(&slot->seq, memory_order_acquire);
		if (seq == c->tail) {
			slot->v = v;
			atomic_store_explicit(&slot->seq, c->tail + 1, memory_order_release);
			++c->tail;
			return 0;
		}
		spsc_backoff(&spin);
	}
}

void *
spmc_chan_recv(spmc_chan_ty *c)
{
	unsigned int spin = 0;
	const size_t pos = atomic_fetch_add_explicit(&c->head, 1, memory_order_acq_rel);
	spmc_slot_ty *const slot = &c->slots[pos & c->mask];
	for (;;) {
		const size_t seq = atomic_load_explicit(&slot->seq, memory_order_acquire);
		if (seq == pos + 1) {
			void *const v = slot->v;
			atomic_store_explicit(&slot->seq, pos + c->cap, memory_order_release);
			return v;
		}
		if (atomic_load_explicit(&c->closed, memory_order_acquire))
			return NULL;
		spsc_backoff(&spin);
	}
}

void *
spmc_chan_try_recv(spmc_chan_ty *c)
{
	for (;;) {
		const size_t head = atomic_load_explicit(&c->head, memory_order_relaxed);
		spmc_slot_ty *const slot = &c->slots[head & c->mask];
		const size_t seq = atomic_load_explicit(&slot->seq, memory_order_acquire);
		if (seq != head + 1)
			return NULL;
		size_t expected = head;
		if (atomic_compare_exchange_weak_explicit(&c->head, &expected, head + 1,
		                                          memory_order_acq_rel, memory_order_relaxed)) {
			void *const v = slot->v;
			atomic_store_explicit(&slot->seq, head + c->cap, memory_order_release);
			return v;
		}
	}
}

void
spmc_chan_close(spmc_chan_ty *c)
{
	atomic_store_explicit(&c->closed, true, memory_order_release);
}

int
spmc_chan_is_closed(spmc_chan_ty *c)
{
	return atomic_load_explicit(&c->closed, memory_order_acquire);
}
