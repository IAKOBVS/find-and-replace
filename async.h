/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef ASYNC_H
#define ASYNC_H

#include "common.h"

/* Concurrency substrate: the only place in the tree that touches pthreads.
 * Two primitives:
 *
 *  - bounded FIFO channels (async_chan_*) for handing work/results between
 *    threads with backpressure;
 *  - a PROCESS-LIFETIME task pool (async_pool_*): N threads loop forever
 *    pulling fn/arg tasks off an internal channel. The pool is started once
 *    (async_default_start) and never shrinks, so the thread count in top/htop
 *    is stable and every subsystem -- the recursive pipeline, TUI rescans --
 *    submits onto the same workers instead of spawning/joining per operation.
 *
 * Nothing here touches stdio or exit(); allocation failures return NULL/-1
 * so callers can degrade or die on their own terms. */

/* Bounded FIFO of void*. SEND blocks while full; RECV blocks while empty;
 * CLOSE releases everyone: blocked/late senders fail with -1, receivers
 * drain the items still queued and then get NULL forever. A channel must be
 * FREEd only after every user is gone. */
typedef struct async_chan_ty async_chan_ty;

async_chan_ty *async_chan_new(size_t cap);
/* 0 = delivered, -1 = channel closed. */
int async_chan_send(async_chan_ty *R ch, void *R v);
/* Next item, or NULL once closed and drained. */
void *async_chan_recv(async_chan_ty *R ch);
void async_chan_close(async_chan_ty *R ch);
void async_chan_free(async_chan_ty *R ch);

/* Process-lifetime task pool. START spawns NWORK worker threads (0 -> one).
 * SUBMIT enqueues FN(ARG); tasks run in arbitrary order. BARRIER blocks the
 * caller until every submitted task has finished. STOP joins everything;
 * call it once, when no more tasks will be submitted (atexit). Returns NULL
 * from START if no worker could be spawned. */
typedef struct async_pool_ty async_pool_ty;
typedef void (*async_task_fn)(void *R arg);

/* One-off joinable thread for roles that must run CONCURRENTLY with the
 * pool (the pipeline's traversal task): a pool slot could starve it, since
 * pool tasks are FIFO and workers block until the traversal feeds them. */
typedef struct async_thread_ty async_thread_ty;

async_thread_ty *async_thread_run(void *(*fn)(void *), void *R arg);
void async_thread_join(async_thread_ty *R th);

/* Plain mutex and manually-reset event (set/wait/clear), so callers never
 * see pthread types -- same rule as the channels above. */
typedef struct async_lock_ty async_lock_ty;
typedef struct async_event_ty async_event_ty;

async_lock_ty *async_lock_new(void);
void async_lock_lock(async_lock_ty *R l);
void async_lock_unlock(async_lock_ty *R l);
void async_lock_free(async_lock_ty *R l);

async_event_ty *async_event_new(void);
void async_event_set(async_event_ty *R e);   /* wake ALL current+future waiters */
void async_event_clear(async_event_ty *R e);
void async_event_wait(async_event_ty *R e);  /* blocks while clear */
int async_event_ready(async_event_ty *R e);
void async_event_free(async_event_ty *R e);

int async_pool_start(size_t nwork);
size_t async_pool_size(void);
void async_pool_submit(async_task_fn fn, void *R arg);
void async_pool_barrier(void);
void async_pool_stop(void);

#endif /* ASYNC_H */
