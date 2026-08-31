/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "async.h"

#include <pthread.h>
#include <stdlib.h>

/* Bounded FIFO ring of void* guarded by one mutex and two condvars. CLOSE
 * flips a flag under the lock and wakes every waiter, so senders fail fast
 * and receivers drain the backlog before seeing NULL. */
struct async_chan_ty {
	pthread_mutex_t mu;
	pthread_cond_t cv_notfull;
	pthread_cond_t cv_notempty;
	void **ring;
	size_t cap;
	size_t head;
	size_t size;
	int closed;
};

async_chan_ty *
async_chan_new(size_t cap)
{
	async_chan_ty *ch;
	if (cap == 0)
		cap = 1;
	ch = (async_chan_ty *)malloc(sizeof(*ch));
	if (jstr_unlikely(ch == NULL))
		return NULL;
	ch->ring = (void **)malloc(cap * sizeof(void *));
	if (jstr_unlikely(ch->ring == NULL)) {
		free(ch);
		return NULL;
	}
	ch->cap = cap;
	ch->head = 0;
	ch->size = 0;
	ch->closed = 0;
	if (jstr_unlikely(pthread_mutex_init(&ch->mu, NULL) != 0)) {
		free(ch->ring);
		free(ch);
		return NULL;
	}
	if (jstr_unlikely(pthread_cond_init(&ch->cv_notfull, NULL) != 0)) {
		pthread_mutex_destroy(&ch->mu);
		free(ch->ring);
		free(ch);
		return NULL;
	}
	if (jstr_unlikely(pthread_cond_init(&ch->cv_notempty, NULL) != 0)) {
		pthread_cond_destroy(&ch->cv_notfull);
		pthread_mutex_destroy(&ch->mu);
		free(ch->ring);
		free(ch);
		return NULL;
	}
	return ch;
}

int
async_chan_send(async_chan_ty *R ch, void *R v)
{
	int ret = 0;
	pthread_mutex_lock(&ch->mu);
	for (;;) {
		if (ch->closed) {
			ret = -1;
			break;
		}
		if (ch->size < ch->cap) {
			ch->ring[(ch->head + ch->size) % ch->cap] = v;
			++ch->size;
			pthread_cond_signal(&ch->cv_notempty);
			break;
		}
		pthread_cond_wait(&ch->cv_notfull, &ch->mu);
	}
	pthread_mutex_unlock(&ch->mu);
	return ret;
}

void *
async_chan_recv(async_chan_ty *R ch)
{
	void *v = NULL;
	pthread_mutex_lock(&ch->mu);
	for (;;) {
		if (ch->size > 0) {
			v = ch->ring[ch->head];
			ch->head = (ch->head + 1) % ch->cap;
			--ch->size;
			pthread_cond_signal(&ch->cv_notfull);
			break;
		}
		if (ch->closed)
			break;
		pthread_cond_wait(&ch->cv_notempty, &ch->mu);
	}
	pthread_mutex_unlock(&ch->mu);
	return v;
}

void
async_chan_close(async_chan_ty *R ch)
{
	pthread_mutex_lock(&ch->mu);
	ch->closed = 1;
	pthread_cond_broadcast(&ch->cv_notfull);
	pthread_cond_broadcast(&ch->cv_notempty);
	pthread_mutex_unlock(&ch->mu);
}

void
async_chan_free(async_chan_ty *R ch)
{
	if (ch == NULL)
		return;
	pthread_cond_destroy(&ch->cv_notempty);
	pthread_cond_destroy(&ch->cv_notfull);
	pthread_mutex_destroy(&ch->mu);
	free(ch->ring);
	free(ch);
}

/* Persistent task pool: NWORK threads block on a task channel; a pending
 * counter under the pool mutex drives BARRIER. Tasks must not submit from
 * within themselves in unbounded recursion (the submitter drains). */
typedef struct async_task_ty {
	async_task_fn fn;
	void *arg;
} async_task_ty;

struct async_pool_ty {
	async_chan_ty *tasks;
	pthread_t *thr;
	size_t nwork;
	size_t pending;
	int stopped;
	pthread_mutex_t mu;
	pthread_cond_t cv_idle;
};

static struct async_pool_ty P = { .mu = PTHREAD_MUTEX_INITIALIZER };

static void *
pool_worker(void *arg)
{
	async_chan_ty *const tasks = (async_chan_ty *)arg;
	for (;;) {
		async_task_ty *task = (async_task_ty *)async_chan_recv(tasks);
		if (task == NULL)
			break;
		task->fn(task->arg);
		free(task);
		pthread_mutex_lock(&P.mu);
		--P.pending;
		if (P.pending == 0)
			pthread_cond_broadcast(&P.cv_idle);
		pthread_mutex_unlock(&P.mu);
	}
	return NULL;
}

struct async_thread_ty {
	pthread_t thr;
	int joined;
};

async_thread_ty *
async_thread_run(void *(*fn)(void *), void *arg)
{
	async_thread_ty *th = (async_thread_ty *)malloc(sizeof(*th));
	if (jstr_unlikely(th == NULL))
		return NULL;
	if (jstr_unlikely(pthread_create(&th->thr, NULL, fn, arg) != 0)) {
		free(th);
		return NULL;
	}
	th->joined = 0;
	return th;
}

void
async_thread_join(async_thread_ty *R th)
{
	if (th == NULL || th->joined)
		return;
	pthread_join(th->thr, NULL);
	free(th);
}

int
async_pool_start(size_t nwork)
{
	size_t k;
	pthread_mutex_lock(&P.mu);
	if (P.nwork > 0) {
		pthread_mutex_unlock(&P.mu);
		return 0;
	}
	pthread_mutex_unlock(&P.mu);

	if (nwork == 0)
		nwork = 1;
	async_chan_ty *const tasks = async_chan_new(nwork + 64);
	if (jstr_unlikely(tasks == NULL))
		return -1;
	pthread_t *const thr = (pthread_t *)malloc(nwork * sizeof(pthread_t));
	if (jstr_unlikely(thr == NULL)) {
		async_chan_free(tasks);
		return -1;
	}
	if (jstr_unlikely(pthread_cond_init(&P.cv_idle, NULL) != 0)) {
		free(thr);
		async_chan_free(tasks);
		return -1;
	}

	pthread_mutex_lock(&P.mu);
	P.tasks = tasks;
	P.thr = thr;
	P.nwork = 0;
	P.pending = 0;
	P.stopped = 0;
	for (k = 0; k < nwork; ++k) {
		if (pthread_create(&P.thr[k], NULL, pool_worker, tasks) != 0)
			break;
		++P.nwork;
	}
	const size_t started = P.nwork;
	pthread_mutex_unlock(&P.mu);

	if (started == 0) {
		pthread_cond_destroy(&P.cv_idle);
		free(thr);
		async_chan_free(tasks);
		return -1;
	}
	return 0;
}

size_t
async_pool_size(void)
{
	pthread_mutex_lock(&P.mu);
	const size_t sz = P.nwork;
	pthread_mutex_unlock(&P.mu);
	return sz;
}

void
async_pool_submit(async_task_fn fn, void *arg)
{
	async_task_ty *task;
	pthread_mutex_lock(&P.mu);
	const int no_pool = (P.nwork == 0 || P.stopped);
	pthread_mutex_unlock(&P.mu);

	if (jstr_unlikely(no_pool)) {
		/* No pool: run inline so callers stay correct without threads. */
		fn(arg);
		return;
	}
	task = (async_task_ty *)malloc(sizeof(*task));
	if (jstr_unlikely(task == NULL)) {
		fn(arg);
		return;
	}
	task->fn = fn;
	task->arg = arg;
	pthread_mutex_lock(&P.mu);
	++P.pending;
	pthread_mutex_unlock(&P.mu);
	if (jstr_unlikely(async_chan_send(P.tasks, task) != 0)) {
		/* Pool stopping underneath us: run inline (we are already
		 * accounting for it). */
		fn(arg);
		pthread_mutex_lock(&P.mu);
		--P.pending;
		if (P.pending == 0)
			pthread_cond_broadcast(&P.cv_idle);
		pthread_mutex_unlock(&P.mu);
		free(task);
	}
}

void
async_pool_barrier(void)
{
	pthread_mutex_lock(&P.mu);
	while (P.pending > 0 && !P.stopped)
		pthread_cond_wait(&P.cv_idle, &P.mu);
	pthread_mutex_unlock(&P.mu);
}

void
async_pool_stop(void)
{
	size_t k;
	pthread_mutex_lock(&P.mu);
	if (P.nwork == 0 || P.stopped) {
		pthread_mutex_unlock(&P.mu);
		return;
	}
	P.stopped = 1;
	const size_t nwork = P.nwork;
	pthread_t *const thr = P.thr;
	async_chan_ty *const tasks = P.tasks;
	pthread_mutex_unlock(&P.mu);

	async_chan_close(tasks);
	for (k = 0; k < nwork; ++k)
		pthread_join(thr[k], NULL);

	pthread_mutex_lock(&P.mu);
	async_chan_free(tasks);
	P.tasks = NULL;
	free(thr);
	P.thr = NULL;
	P.nwork = 0;
	pthread_cond_destroy(&P.cv_idle);
	pthread_mutex_unlock(&P.mu);
}

/* Mutex wrapper. */
struct async_lock_ty {
	pthread_mutex_t mu;
};

async_lock_ty *
async_lock_new(void)
{
	async_lock_ty *l = (async_lock_ty *)malloc(sizeof(*l));
	if (jstr_unlikely(l == NULL))
		return NULL;
	if (jstr_unlikely(pthread_mutex_init(&l->mu, NULL) != 0)) {
		free(l);
		return NULL;
	}
	return l;
}

void
async_lock_lock(async_lock_ty *R l)
{
	pthread_mutex_lock(&l->mu);
}

void
async_lock_unlock(async_lock_ty *R l)
{
	pthread_mutex_unlock(&l->mu);
}

void
async_lock_free(async_lock_ty *R l)
{
	if (l == NULL)
		return;
	pthread_mutex_destroy(&l->mu);
	free(l);
}

/* Manually-reset event: one mutex + condvar + flag. */
struct async_event_ty {
	pthread_mutex_t mu;
	pthread_cond_t cv;
	int ready;
};

async_event_ty *
async_event_new(void)
{
	async_event_ty *e = (async_event_ty *)malloc(sizeof(*e));
	if (jstr_unlikely(e == NULL))
		return NULL;
	e->ready = 0;
	if (jstr_unlikely(pthread_mutex_init(&e->mu, NULL) != 0)) {
		free(e);
		return NULL;
	}
	if (jstr_unlikely(pthread_cond_init(&e->cv, NULL) != 0)) {
		pthread_mutex_destroy(&e->mu);
		free(e);
		return NULL;
	}
	return e;
}

void
async_event_set(async_event_ty *R e)
{
	pthread_mutex_lock(&e->mu);
	e->ready = 1;
	pthread_cond_broadcast(&e->cv);
	pthread_mutex_unlock(&e->mu);
}

void
async_event_clear(async_event_ty *R e)
{
	pthread_mutex_lock(&e->mu);
	e->ready = 0;
	pthread_mutex_unlock(&e->mu);
}

void
async_event_wait(async_event_ty *R e)
{
	pthread_mutex_lock(&e->mu);
	while (!e->ready)
		pthread_cond_wait(&e->cv, &e->mu);
	pthread_mutex_unlock(&e->mu);
}

int
async_event_ready(async_event_ty *R e)
{
	return e->ready;
}

void
async_event_free(async_event_ty *R e)
{
	if (e == NULL)
		return;
	pthread_cond_destroy(&e->cv);
	pthread_mutex_destroy(&e->mu);
	free(e);
}
