/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "../../include/spsc.h"

#include <stdint.h>
#include <stdio.h>
#include "../../include/thread_compat.h"
#include <time.h>

#define N_ITEMS 200000
#define N_BURST 8

static int failures;

#define CHECK(cond, msg)                                  \
	do {                                              \
		if (!(cond)) {                            \
			fprintf(stderr, "FAIL: %s\n", msg); \
			++failures;                       \
		}                                         \
	} while (0)

typedef struct {
	spsc_chan_ty *ch;
	size_t n;
	int rc;
} send_ctx_ty;

typedef struct {
	spsc_chan_ty *ch;
	size_t n;
	int rc;
} recv_ctx_ty;

static far_thread_ret_ty
send_many(void *arg)
{
	send_ctx_ty *ctx = (send_ctx_ty *)(void *)arg;
	ctx->rc = 0;
	for (size_t i = 0; i < ctx->n; ++i) {
		if (spsc_chan_send(ctx->ch, (void *)(uintptr_t)(i + 1)) != 0) {
			ctx->rc = -1;
			break;
		}
	}
	return FAR_THREAD_RETURN;
}

static far_thread_ret_ty
recv_many(void *arg)
{
	recv_ctx_ty *ctx = (recv_ctx_ty *)(void *)arg;
	ctx->rc = 0;
	for (size_t i = 0; i < ctx->n; ++i) {
		void *v = spsc_chan_recv(ctx->ch);
		if (v == NULL) {
			ctx->rc = -1;
			break;
		}
		if ((uintptr_t)v != i + 1) {
			ctx->rc = -2;
			break;
		}
	}
	return FAR_THREAD_RETURN;
}

static far_thread_ret_ty
send_until_closed(void *arg)
{
	send_ctx_ty *ctx = (send_ctx_ty *)(void *)arg;
	ctx->rc = 0;
	for (size_t i = 0;; ++i) {
		if (spsc_chan_send(ctx->ch, (void *)(uintptr_t)(i + 1)) != 0) {
			ctx->rc = -1;
			break;
		}
	}
	return FAR_THREAD_RETURN;
}

static far_thread_ret_ty
recv_until_closed(void *arg)
{
	recv_ctx_ty *ctx = (recv_ctx_ty *)(void *)arg;
	ctx->rc = 0;
	if (spsc_chan_recv(ctx->ch) != NULL)
		ctx->rc = 1;
	else
		ctx->rc = -1;
	return FAR_THREAD_RETURN;
}

static void
test_fifo(void)
{
	spsc_chan_ty *ch = spsc_chan_new(8);
	CHECK(ch != NULL, "new failed");
	if (ch == NULL)
		return;
	send_ctx_ty sc = { ch, N_ITEMS, 0 };
	recv_ctx_ty rc = { ch, N_ITEMS, 0 };
	far_thread_ty thr;
	CHECK(FAR_THREAD_CREATE(&thr, send_many, &sc) == FAR_THREAD_SUCCESS, "create producer failed");
	CHECK(recv_many(&rc) == 0, "consumer crashed");
	CHECK(FAR_THREAD_JOIN(thr) == FAR_THREAD_SUCCESS, "join producer failed");
	CHECK(sc.rc == 0, "producer reported closed");
	CHECK(rc.rc == 0, "consumer saw wrong order or closed");
	spsc_chan_close(ch);
	CHECK(spsc_chan_recv(ch) == NULL, "recv after close not NULL");
	spsc_chan_free(ch);
}

static void
test_new_edge(void)
{
	spsc_chan_free(NULL);
	CHECK(spsc_chan_new((size_t)-1) == NULL, "overflowing cap should fail");
#ifndef FAR_USE_PTHREAD
	CHECK(spsc_chan_new((size_t)1 << 62) == NULL, "overflowing slot bytes should fail");
#endif
	spsc_chan_ty *ch = spsc_chan_new(0);
	CHECK(ch != NULL, "zero cap should round up");
	if (ch == NULL)
		return;
	CHECK(spsc_chan_is_closed(ch) == 0, "fresh channel marked closed");
	spsc_chan_close(ch);
	CHECK(spsc_chan_is_closed(ch) == 1, "close not visible");
	spsc_chan_free(ch);
}

static void
test_close_drains(void)
{
	spsc_chan_ty *ch = spsc_chan_new(8);
	CHECK(ch != NULL, "new failed");
	if (ch == NULL)
		return;
	for (size_t i = 0; i < N_BURST; ++i)
		CHECK(spsc_chan_send(ch, (void *)(uintptr_t)(i + 1)) == 0, "send before close failed");
	spsc_chan_close(ch);
	for (size_t i = 0; i < N_BURST; ++i) {
		void *v = spsc_chan_recv(ch);
		CHECK(v != NULL, "drain lost queued item");
		CHECK(v == NULL || (uintptr_t)v == i + 1, "drain order changed");
	}
	CHECK(spsc_chan_recv(ch) == NULL, "drained channel not NULL");
	CHECK(spsc_chan_send(ch, (void *)1) == -1, "send after close did not fail");
	spsc_chan_free(ch);
}

static void
test_try_send(void)
{
	spsc_chan_ty *ch = spsc_chan_new(4);
	CHECK(ch != NULL, "new failed");
	if (ch == NULL)
		return;
	CHECK(spsc_chan_try_send(ch, (void *)(uintptr_t)1) == 0, "try_send 1 failed");
	CHECK(spsc_chan_try_send(ch, (void *)(uintptr_t)2) == 0, "try_send 2 failed");
	CHECK(spsc_chan_try_send(ch, (void *)(uintptr_t)3) == 0, "try_send 3 failed");
	CHECK(spsc_chan_try_send(ch, (void *)(uintptr_t)4) == 0, "try_send 4 failed");
	CHECK(spsc_chan_try_send(ch, (void *)(uintptr_t)5) == -1, "try_send full did not fail");
	CHECK(spsc_chan_recv(ch) == (void *)(uintptr_t)1, "try_send order changed");
	CHECK(spsc_chan_try_send(ch, (void *)(uintptr_t)5) == 0, "try_send after space failed");
	spsc_chan_close(ch);
	CHECK(spsc_chan_try_send(ch, (void *)(uintptr_t)6) == -1, "try_send after close did not fail");
	spsc_chan_free(ch);
}

static void
test_blocked_producer(void)
{
	spsc_chan_ty *ch = spsc_chan_new(2);
	CHECK(ch != NULL, "new failed");
	if (ch == NULL)
		return;
	send_ctx_ty sc = { ch, 0, 0 };
	far_thread_ty thr;
	CHECK(FAR_THREAD_CREATE(&thr, send_until_closed, &sc) == FAR_THREAD_SUCCESS, "create producer failed");
	struct timespec ts = { 0, 5000000 };
	nanosleep(&ts, NULL);
	CHECK(!spsc_chan_is_closed(ch), "channel closed too early");
	spsc_chan_close(ch);
	CHECK(FAR_THREAD_JOIN(thr) == FAR_THREAD_SUCCESS, "join blocked producer failed");
	CHECK(sc.rc == -1, "blocked producer was not released by close");
	while (spsc_chan_recv(ch) != NULL) {}
	spsc_chan_free(ch);
}

static void
test_blocked_consumer(void)
{
	spsc_chan_ty *ch = spsc_chan_new(2);
	CHECK(ch != NULL, "new failed");
	if (ch == NULL)
		return;
	recv_ctx_ty rc = { ch, 0, 0 };
	far_thread_ty thr;
	CHECK(FAR_THREAD_CREATE(&thr, recv_until_closed, &rc) == FAR_THREAD_SUCCESS, "create consumer failed");
	struct timespec ts = { 0, 5000000 };
	nanosleep(&ts, NULL);
	spsc_chan_close(ch);
	CHECK(FAR_THREAD_JOIN(thr) == FAR_THREAD_SUCCESS, "join blocked consumer failed");
	CHECK(rc.rc == -1, "blocked consumer was not released by close");
	spsc_chan_free(ch);
}

static void
test_init_static(void)
{
	void *slots[8];
	spsc_chan_ty ch;
	CHECK(spsc_chan_init(&ch, slots, 8) == 0, "static init failed");
	CHECK(spsc_chan_init(&ch, slots, 3) == -1, "non-power-of-two cap accepted");
	CHECK(spsc_chan_init(&ch, slots, 0) == -1, "zero cap accepted");
	CHECK(spsc_chan_init(&ch, NULL, 8) == -1, "NULL slots accepted");
	CHECK(spsc_chan_init(&ch, slots, 8) == 0, "re-init failed");
	CHECK(spsc_chan_is_closed(&ch) == 0, "re-init kept closed");
	for (size_t i = 0; i < N_BURST; ++i)
		CHECK(spsc_chan_send(&ch, (void *)(uintptr_t)(i + 1)) == 0, "static send failed");
	for (size_t i = 0; i < N_BURST; ++i) {
		void *v = spsc_chan_recv(&ch);
		CHECK(v == NULL || (uintptr_t)v == i + 1, "static order changed");
	}
	spsc_chan_close(&ch);
	CHECK(spsc_chan_recv(&ch) == NULL, "static close drain failed");
	CHECK(spsc_chan_send(&ch, (void *)1) == -1, "static send after close did not fail");
}

int
main(void)
{
	test_init_static();
	test_fifo();
	test_new_edge();
	test_close_drains();
	test_try_send();
	test_blocked_producer();
	test_blocked_consumer();
	if (failures != 0) {
		fprintf(stderr, "%d spsc check(s) failed\n", failures);
		return 1;
	}
	printf("spsc: all checks passed\n");
	return 0;
}
