/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "spsc.h"

#include <sched.h>
#include <stdlib.h>
#include <time.h>

#define SPSC_YIELD_SPIN 64
#define SPSC_SLEEP_NS   100000

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

spsc_chan_ty *
spsc_chan_new(size_t cap)
{
	size_t n = 2;
	while (n < cap) {
		if (n > (size_t)-1 / 2)
			return NULL;
		n <<= 1;
	}
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

void
spsc_chan_free(spsc_chan_ty *c)
{
	if (c == NULL)
		return;
	if (c->owned)
		free(c->slots);
	free(c);
}

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

void
spsc_chan_close(spsc_chan_ty *c)
{
	atomic_store_explicit(&c->closed, true, memory_order_release);
}

int
spsc_chan_is_closed(spsc_chan_ty *c)
{
	return atomic_load_explicit(&c->closed, memory_order_acquire);
}
