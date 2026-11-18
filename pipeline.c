/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "pipeline.h"
#include "traverse.h"
#include "process.h"
#include "ui.h"
#include "terminal.h"
#include "grep_worker.h"
#include "spmc.h"
#include "spsc.h"
#include "thread_compat.h"

#include <errno.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define PIPELINE_DEPTH 256
#define PIPELINE_DONE_DEPTH 128
#define PIPELINE_CMD_DEPTH 16
#define PIPELINE_UI_DEPTH 16
#define PIPELINE_GREP_WORK_DEPTH 64
#define PIPELINE_GREP_MSG_DEPTH 64
#define PIPELINE_GREP_RETIRE_DEPTH 8

typedef struct b_worker_ty {
	alignas(64) spsc_chan_ty done;
	alignas(64) void *done_slots[PIPELINE_DONE_DEPTH];
	alignas(64) spsc_chan_ty grep_work;
	alignas(64) void *grep_work_slots[PIPELINE_GREP_WORK_DEPTH];
} b_worker_ty;

typedef struct pipeline_state_ty {
	alignas(64) spsc_chan_ty cmd;
	alignas(64) void *cmd_slots[PIPELINE_CMD_DEPTH];
	alignas(64) spmc_chan_ty work;
	spmc_slot_ty *work_slots;
	alignas(64) spsc_chan_ty ui_cmd;
	alignas(64) void *ui_cmd_slots[PIPELINE_UI_DEPTH];
	alignas(64) spsc_chan_ty ui_ack;
	alignas(64) void *ui_ack_slots[PIPELINE_UI_DEPTH];
	alignas(64) spsc_chan_ty grep_msg;
	alignas(64) void *grep_msg_slots[PIPELINE_GREP_MSG_DEPTH];
	alignas(64) spsc_chan_ty grep_cfg;
	alignas(64) void *grep_cfg_slots[PIPELINE_UI_DEPTH];
	alignas(64) spsc_chan_ty grep_retire;
	alignas(64) void *grep_retire_slots[PIPELINE_GREP_RETIRE_DEPTH];
	b_worker_ty *workers;
	far_thread_ty *b_threads;
	size_t worker_count;
	size_t requested_workers;
	far_thread_ty a_thread;
	far_thread_ty c_thread;
	far_thread_ty d_thread;
	int ui_live;
	int started;
} pipeline_state_ty;

static pipeline_state_ty P;
static _Atomic(root_ctx_ty *) current_root;
static atomic_ulong root_epoch;
static atomic_bool workers_stop;

static size_t
parse_env_workers(const char *s)
{
	if (s == NULL || *s == '\0')
		return 0;
	char *end;
	errno = 0;
	const unsigned long v = strtoul(s, &end, 10);
	if (errno != 0 || *end != '\0' || v == 0)
		return 0;
	return (size_t)v;
}

static size_t
default_workers(void)
{
	const size_t env = parse_env_workers(getenv("FAR_THREADS"));
	if (env != 0)
		return env;
	long n = sysconf(_SC_NPROCESSORS_ONLN);
	if (n < 1)
		n = 1;
	return (size_t)n * 2;
}

void
pipeline_set_workers(size_t count)
{
	if (count == 0)
		count = 1;
	if (!P.started)
		P.requested_workers = count;
}

size_t
pipeline_worker_count(void)
{
	if (P.worker_count != 0)
		return P.worker_count;
	if (P.requested_workers != 0)
		return P.requested_workers;
	return default_workers();
}

void
pipeline_root_set(root_ctx_ty *root)
{
	atomic_store_explicit(&current_root, root, memory_order_release);
	atomic_fetch_add_explicit(&root_epoch, 1, memory_order_acq_rel);
}

root_ctx_ty *
pipeline_root_get(void)
{
	return atomic_load_explicit(&current_root, memory_order_acquire);
}

unsigned long
pipeline_root_epoch(void)
{
	return atomic_load_explicit(&root_epoch, memory_order_acquire);
}

int
pipeline_stopping(void)
{
	return atomic_load_explicit(&workers_stop, memory_order_acquire);
}

root_ctx_ty *
pipeline_cmd_recv(void)
{
	return (root_ctx_ty *)spsc_chan_recv(&P.cmd);
}

int
pipeline_work_send(far_job_ty *job)
{
	return spmc_chan_send(&P.work, job);
}

far_job_ty *
pipeline_work_try_recv(void)
{
	return (far_job_ty *)spmc_chan_try_recv(&P.work);
}

int
pipeline_done_send(size_t worker, far_result_ty *res)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return -1;
	return spsc_chan_send(&P.workers[worker].done, res);
}

far_result_ty *
pipeline_done_try_recv(size_t worker)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return NULL;
	return (far_result_ty *)spsc_chan_try_recv(&P.workers[worker].done);
}

int
pipeline_grep_work_send(size_t worker, far_result_ty *res)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return -1;
	return spsc_chan_send(&P.workers[worker].grep_work, res);
}

far_result_ty *
pipeline_grep_work_try_recv(size_t worker)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return NULL;
	return (far_result_ty *)spsc_chan_try_recv(&P.workers[worker].grep_work);
}

int
pipeline_grep_msg_send(far_grep_msg_ty *msg)
{
	return spsc_chan_send(&P.grep_msg, msg);
}

far_grep_msg_ty *
pipeline_grep_msg_recv(void)
{
	return (far_grep_msg_ty *)spsc_chan_recv(&P.grep_msg);
}

far_grep_msg_ty *
pipeline_grep_msg_try_recv(void)
{
	return (far_grep_msg_ty *)spsc_chan_try_recv(&P.grep_msg);
}

int
pipeline_grep_cfg_send(grep_cfg_ty *cfg)
{
	return spsc_chan_send(&P.grep_cfg, cfg);
}

grep_cfg_ty *
pipeline_grep_cfg_recv(void)
{
	return (grep_cfg_ty *)spsc_chan_recv(&P.grep_cfg);
}

grep_cfg_ty *
pipeline_grep_cfg_try_recv(void)
{
	return (grep_cfg_ty *)spsc_chan_try_recv(&P.grep_cfg);
}

int
pipeline_grep_retire_try_send(grep_lines_ty *lines)
{
	return spsc_chan_try_send(&P.grep_retire, lines);
}

grep_lines_ty *
pipeline_grep_retire_try_recv(void)
{
	return (grep_lines_ty *)spsc_chan_try_recv(&P.grep_retire);
}

far_ui_cmd_ty *
pipeline_ui_cmd_recv(void)
{
	return (far_ui_cmd_ty *)spsc_chan_recv(&P.ui_cmd);
}

far_ui_cmd_ty *
pipeline_ui_cmd_try_recv(void)
{
	return (far_ui_cmd_ty *)spsc_chan_try_recv(&P.ui_cmd);
}

int
pipeline_ui_ack_send(int status)
{
	return spsc_chan_send(&P.ui_ack, (void *)(uintptr_t)(status + 1));
}

int
pipeline_ui_ack_recv(void)
{
	void *const v = spsc_chan_recv(&P.ui_ack);
	if (v == NULL)
		return -1;
	return (int)(uintptr_t)v - 1;
}

int
pipeline_ui_finish(void)
{
	far_ui_cmd_ty cmd;
	cmd.kind = FAR_UI_END;
	cmd.root = NULL;
	if (jstr_unlikely(spsc_chan_send(&P.ui_cmd, &cmd) != 0))
		return -1;
	return pipeline_ui_ack_recv();
}

static void
free_state(void)
{
	free(P.workers);
	free(P.b_threads);
	free(P.work_slots);
	P.workers = NULL;
	P.b_threads = NULL;
	P.work_slots = NULL;
	P.worker_count = 0;
}

static void
stop_ui_and_grep(void)
{
	grep_cfg_ty gstop;
	gstop.kind = GREP_CFG_STOP;
	(void)spsc_chan_send(&P.grep_cfg, &gstop);
	FAR_THREAD_JOIN(P.d_thread);
	far_ui_cmd_ty stop;
	stop.kind = FAR_UI_STOP;
	stop.root = NULL;
	(void)spsc_chan_send(&P.ui_cmd, &stop);
	FAR_THREAD_JOIN(P.c_thread);
}

int
pipeline_start(void)
{
	if (P.started)
		return 0;
	if (P.requested_workers == 0)
		P.requested_workers = default_workers();
	if (P.requested_workers == 0)
		P.requested_workers = 1;
	if (P.requested_workers > (size_t)-1 / sizeof(b_worker_ty))
		return -1;
	P.worker_count = P.requested_workers;
	atomic_init(&current_root, NULL);
	atomic_init(&root_epoch, 0);
	atomic_init(&workers_stop, false);
	P.workers = (b_worker_ty *)calloc(P.worker_count, sizeof *P.workers);
	P.b_threads = (far_thread_ty *)calloc(P.worker_count, sizeof *P.b_threads);
	P.work_slots = (spmc_slot_ty *)calloc(PIPELINE_DEPTH, sizeof *P.work_slots);
	if (jstr_unlikely(!P.workers || !P.b_threads || !P.work_slots)) {
		free_state();
		return -1;
	}
	if (jstr_unlikely(spsc_chan_init(&P.cmd, P.cmd_slots, PIPELINE_CMD_DEPTH) != 0 ||
	                 spmc_chan_init(&P.work, P.work_slots, PIPELINE_DEPTH) != 0 ||
	                 spsc_chan_init(&P.ui_cmd, P.ui_cmd_slots, PIPELINE_UI_DEPTH) != 0 ||
	                 spsc_chan_init(&P.ui_ack, P.ui_ack_slots, PIPELINE_UI_DEPTH) != 0 ||
	                 spsc_chan_init(&P.grep_msg, P.grep_msg_slots, PIPELINE_GREP_MSG_DEPTH) != 0 ||
	                 spsc_chan_init(&P.grep_cfg, P.grep_cfg_slots, PIPELINE_UI_DEPTH) != 0 ||
	                 spsc_chan_init(&P.grep_retire, P.grep_retire_slots, PIPELINE_GREP_RETIRE_DEPTH) != 0)) {
		free_state();
		return -1;
	}
	for (size_t i = 0; i < P.worker_count; ++i) {
		if (jstr_unlikely(spsc_chan_init(&P.workers[i].done, P.workers[i].done_slots, PIPELINE_DONE_DEPTH) != 0 ||
		                 spsc_chan_init(&P.workers[i].grep_work, P.workers[i].grep_work_slots, PIPELINE_GREP_WORK_DEPTH) != 0)) {
			free_state();
			return -1;
		}
	}
	if (jstr_unlikely(FAR_THREAD_CREATE(&P.d_thread, grep_worker_thread, NULL) != FAR_THREAD_SUCCESS)) {
		free_state();
		return -1;
	}
	if (jstr_unlikely(FAR_THREAD_CREATE(&P.c_thread, terminal_ui_thread, NULL) != FAR_THREAD_SUCCESS)) {
		grep_cfg_ty stop;
		stop.kind = GREP_CFG_STOP;
		(void)spsc_chan_send(&P.grep_cfg, &stop);
		FAR_THREAD_JOIN(P.d_thread);
		free_state();
		return -1;
	}
	size_t started = 0;
	for (; started < P.worker_count; ++started) {
		if (jstr_unlikely(FAR_THREAD_CREATE(&P.b_threads[started], process_thread, (void *)(uintptr_t)started) != FAR_THREAD_SUCCESS))
			break;
	}
	if (started != P.worker_count) {
		atomic_store_explicit(&workers_stop, true, memory_order_release);
		pipeline_root_set(NULL);
		spmc_chan_close(&P.work);
		for (size_t i = 0; i < started; ++i)
			FAR_THREAD_JOIN(P.b_threads[i]);
		stop_ui_and_grep();
		free_state();
		return -1;
	}
	if (jstr_unlikely(FAR_THREAD_CREATE(&P.a_thread, traverse_thread, NULL) != FAR_THREAD_SUCCESS)) {
		atomic_store_explicit(&workers_stop, true, memory_order_release);
		pipeline_root_set(NULL);
		spmc_chan_close(&P.work);
		for (size_t i = 0; i < P.worker_count; ++i)
			FAR_THREAD_JOIN(P.b_threads[i]);
		stop_ui_and_grep();
		free_state();
		return -1;
	}
	P.ui_live = 0;
	P.started = 1;
	return 0;
}

void
pipeline_shutdown(void)
{
	if (!P.started)
		return;
	atomic_store_explicit(&workers_stop, true, memory_order_release);
	(void)spsc_chan_send(&P.cmd, NULL);
	FAR_THREAD_JOIN(P.a_thread);
	for (size_t i = 0; i < P.worker_count; ++i)
		FAR_THREAD_JOIN(P.b_threads[i]);
	stop_ui_and_grep();
	P.ui_live = 0;
	P.started = 0;
	free_state();
}

static void
process_result(far_result_ty *R res, root_ctx_ty *R root, int *R failed, int *R canceled)
{
	if (!*canceled && !res->canceled) {
		if (res->pr.err) {
			if (G.confirm_pass && (G.mode & MODE_CONFIRM)) {
				*failed = 1;
				*canceled = 1;
				atomic_store_explicit(&root->cancel, true, memory_order_release);
			} else {
				++root->a->err_count;
			}
		} else if (jstr_chk(ui_result(res, root->a))) {
			if (G.confirm_pass && (G.mode & MODE_CONFIRM)) {
				*failed = 1;
				*canceled = 1;
				atomic_store_explicit(&root->cancel, true, memory_order_release);
			} else {
				++root->a->err_count;
			}
		}
	}
	ui_result_free(res);
}

int
pipeline_run(root_ctx_ty *R root)
{
	if (jstr_unlikely(!P.started) && pipeline_start() != 0)
		return JSTR_RET_ERR;
	atomic_init(&root->cancel, false);
	atomic_init(&root->total, 0);
	atomic_init(&root->jobs_done, 0);
	atomic_init(&root->workers_done, 0);
	atomic_init(&root->eos_taken, false);
	atomic_init(&root->eos_sent, false);
	atomic_init(&root->ftw_ret, JSTR_RET_SUCC);
	atomic_init(&root->prod_errs, 0);
	root->seq = 0;
	if (G.mode & MODE_GREP && G.grep_collect && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
		far_ui_cmd_ty cmd;
		cmd.kind = FAR_UI_ROOT;
		cmd.root = root;
		if (jstr_unlikely(spsc_chan_send(&P.ui_cmd, &cmd) != 0))
			return JSTR_RET_ERR;
		if (jstr_unlikely(spsc_chan_send(&P.cmd, root) != 0))
			return JSTR_RET_ERR;
		P.ui_live = 1;
		const int status = pipeline_ui_ack_recv();
		if (status < 0)
			return JSTR_RET_ERR;
		if (status != 0)
			return JSTR_RET_ERR;
		return atomic_load_explicit(&root->ftw_ret, memory_order_acquire);
	}
	if (jstr_unlikely(spsc_chan_send(&P.cmd, root) != 0))
		return JSTR_RET_ERR;
	int failed = 0;
	int canceled = 0;
	int ret = JSTR_RET_SUCC;
	size_t eos = 0;
	size_t data_results = 0;
	unsigned int spin = 0;
	while (eos < 1 || data_results < atomic_load_explicit(&root->total, memory_order_acquire)) {
		int did = 0;
		for (size_t w = 0; w < P.worker_count; ++w) {
			far_result_ty *res;
			while ((res = pipeline_done_try_recv(w)) != NULL) {
				did = 1;
				if (res->kind == FAR_RES_EOS) {
					ui_result_free(res);
					++eos;
					continue;
				}
				++data_results;
				process_result(res, root, &failed, &canceled);
			}
		}
		if (did)
			spin = 0;
		else
			spsc_backoff(&spin);
	}
	root->a->err_count += atomic_load_explicit(&root->prod_errs, memory_order_acquire);
	ret = atomic_load_explicit(&root->ftw_ret, memory_order_acquire);
	if (failed)
		return JSTR_RET_ERR;
	return ret;
}
