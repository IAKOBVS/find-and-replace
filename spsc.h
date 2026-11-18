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

int spsc_chan_init(spsc_chan_ty *c, void **slots, size_t cap);
void spsc_backoff(unsigned int *spin);
spsc_chan_ty *spsc_chan_new(size_t cap);
void spsc_chan_free(spsc_chan_ty *c);
int spsc_chan_send(spsc_chan_ty *c, void *v);
int spsc_chan_try_send(spsc_chan_ty *c, void *v);
void *spsc_chan_recv(spsc_chan_ty *c);
void *spsc_chan_try_recv(spsc_chan_ty *c);
void spsc_chan_close(spsc_chan_ty *c);
int spsc_chan_is_closed(spsc_chan_ty *c);

#endif /* SPSC_H */
