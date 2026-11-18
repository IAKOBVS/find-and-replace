/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "../../spmc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../thread_compat.h"

#define N_CONSUMERS 4
#define N_PER       5000
#define N_ITEMS     (N_CONSUMERS * N_PER)
#define CAP         8

static int failures;

#define CHECK(cond, msg)                                  \
	do {                                              \
		if (!(cond)) {                            \
			fprintf(stderr, "FAIL: %s\n", msg); \
			++failures;                       \
		}                                         \
	} while (0)

typedef struct {
	spmc_chan_ty *ch;
	atomic_int *seen;
} consume_ctx_ty;

static far_thread_ret_ty
consume(void *arg)
{
	consume_ctx_ty *ctx = (consume_ctx_ty *)(void *)arg;
	for (size_t i = 0; i < N_PER; ++i) {
		void *v = spmc_chan_recv(ctx->ch);
		if (v == NULL)
			return (far_thread_ret_ty)1;
		const size_t idx = (size_t)(uintptr_t)v - 1;
		if (idx >= N_ITEMS)
			return (far_thread_ret_ty)2;
		atomic_fetch_add_explicit(&ctx->seen[idx], 1, memory_order_relaxed);
	}
	return FAR_THREAD_RETURN;
}

static void
test_multi_consumer(void)
{
	spmc_slot_ty slots[CAP];
	spmc_chan_ty ch;
	CHECK(spmc_chan_init(&ch, slots, CAP) == 0, "init failed");
	atomic_int *seen = calloc(N_ITEMS, sizeof *seen);
	CHECK(seen != NULL, "calloc failed");
	if (seen == NULL)
		return;
	far_thread_ty threads[N_CONSUMERS];
	consume_ctx_ty ctx = { &ch, seen };
	for (size_t i = 0; i < N_CONSUMERS; ++i)
		CHECK(FAR_THREAD_CREATE(&threads[i], consume, &ctx) == FAR_THREAD_SUCCESS, "create consumer failed");
	for (size_t i = 0; i < N_ITEMS; ++i)
		CHECK(spmc_chan_send(&ch, (void *)(uintptr_t)(i + 1)) == 0, "send failed");
	for (size_t i = 0; i < N_CONSUMERS; ++i)
		CHECK(FAR_THREAD_JOIN(threads[i]) == FAR_THREAD_SUCCESS, "join failed");
	for (size_t i = 0; i < N_ITEMS; ++i) {
		if (atomic_load_explicit(&seen[i], memory_order_relaxed) != 1) {
			CHECK(0, "item missing or duplicated");
			break;
		}
	}
	free(seen);
}

typedef struct {
	spmc_chan_ty *ch;
	void *result;
} close_ctx_ty;

static far_thread_ret_ty
recv_one(void *arg)
{
	close_ctx_ty *ctx = (close_ctx_ty *)(void *)arg;
	ctx->result = spmc_chan_recv(ctx->ch);
	return FAR_THREAD_RETURN;
}

static void
test_try_recv(void)
{
	spmc_slot_ty slots[CAP];
	spmc_chan_ty ch;
	CHECK(spmc_chan_init(&ch, slots, CAP) == 0, "init failed");
	CHECK(spmc_chan_try_recv(&ch) == NULL, "try_recv empty not NULL");
	for (size_t i = 0; i < 3; ++i)
		CHECK(spmc_chan_send(&ch, (void *)(uintptr_t)(i + 1)) == 0, "send failed");
	for (size_t i = 0; i < 3; ++i)
		CHECK(spmc_chan_try_recv(&ch) == (void *)(uintptr_t)(i + 1), "try_recv order changed");
	CHECK(spmc_chan_try_recv(&ch) == NULL, "try_recv drained not NULL");
	spmc_chan_close(&ch);
	CHECK(spmc_chan_try_recv(&ch) == NULL, "try_recv after close not NULL");
}

static void
test_close_wakes(void)
{
	spmc_slot_ty slots[CAP];
	spmc_chan_ty ch;
	CHECK(spmc_chan_init(&ch, slots, CAP) == 0, "init failed");
	close_ctx_ty ctx = { &ch, (void *)(uintptr_t)1 };
	far_thread_ty thr;
	CHECK(FAR_THREAD_CREATE(&thr, recv_one, &ctx) == FAR_THREAD_SUCCESS, "create consumer failed");
	spmc_chan_close(&ch);
	CHECK(FAR_THREAD_JOIN(thr) == FAR_THREAD_SUCCESS, "join failed");
	CHECK(ctx.result == NULL, "recv after close not NULL");
	CHECK(spmc_chan_send(&ch, (void *)(uintptr_t)2) == -1, "send after close did not fail");
}

static void
test_invalid_cap(void)
{
	spmc_slot_ty slots[CAP];
	spmc_chan_ty ch;
	CHECK(spmc_chan_init(&ch, slots, 3) == -1, "non-power-of-two cap accepted");
	CHECK(spmc_chan_init(&ch, slots, 0) == -1, "zero cap accepted");
	CHECK(spmc_chan_init(&ch, NULL, CAP) == -1, "NULL slots accepted");
	CHECK(spmc_chan_init(&ch, slots, CAP) == 0, "valid init failed");
}

int
main(void)
{
	test_invalid_cap();
	test_multi_consumer();
	test_try_recv();
	test_close_wakes();
	if (failures != 0)
		return 1;
	puts("spmc: all checks passed");
	return 0;
}
