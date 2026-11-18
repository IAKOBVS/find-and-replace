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

int spmc_chan_init(spmc_chan_ty *c, spmc_slot_ty *slots, size_t cap);
int spmc_chan_send(spmc_chan_ty *c, void *v);
void *spmc_chan_recv(spmc_chan_ty *c);
void *spmc_chan_try_recv(spmc_chan_ty *c);
void spmc_chan_close(spmc_chan_ty *c);
int spmc_chan_is_closed(spmc_chan_ty *c);

#endif /* SPMC_H */
