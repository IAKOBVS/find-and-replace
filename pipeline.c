/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "pipeline.h"
#include "traverse.h"
#include "process.h"
#include "ui.h"
#include "terminal.h"
#include "grep_worker.h"
#include "spsc.h"
#include "thread_compat.h"

#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>

#define PIPELINE_DEPTH 128
#define PIPELINE_CMD_DEPTH 16
#define PIPELINE_UI_DEPTH 16
#define PIPELINE_GREP_WORK_DEPTH 64
#define PIPELINE_GREP_MSG_DEPTH 64
#define PIPELINE_GREP_RETIRE_DEPTH 8

typedef struct pipeline_state_ty {
	alignas(64) spsc_chan_ty cmd;
	alignas(64) void *cmd_slots[PIPELINE_CMD_DEPTH];
	alignas(64) spsc_chan_ty work;
	alignas(64) void *work_slots[PIPELINE_DEPTH];
	alignas(64) spsc_chan_ty done;
	alignas(64) void *done_slots[PIPELINE_DEPTH];
	alignas(64) spsc_chan_ty ui_cmd;
	alignas(64) void *ui_cmd_slots[PIPELINE_UI_DEPTH];
	alignas(64) spsc_chan_ty ui_ack;
	alignas(64) void *ui_ack_slots[PIPELINE_UI_DEPTH];
	alignas(64) spsc_chan_ty grep_work;
	alignas(64) void *grep_work_slots[PIPELINE_GREP_WORK_DEPTH];
	alignas(64) spsc_chan_ty grep_msg;
	alignas(64) void *grep_msg_slots[PIPELINE_GREP_MSG_DEPTH];
	alignas(64) spsc_chan_ty grep_cfg;
	alignas(64) void *grep_cfg_slots[PIPELINE_UI_DEPTH];
	alignas(64) spsc_chan_ty grep_retire;
	alignas(64) void *grep_retire_slots[PIPELINE_GREP_RETIRE_DEPTH];
	far_thread_ty a_thread;
	far_thread_ty b_thread;
	far_thread_ty c_thread;
	far_thread_ty d_thread;
	int ui_live;
	int started;
} pipeline_state_ty;

static pipeline_state_ty P;

root_ctx_ty *
pipeline_cmd_recv(void)
{
	return (root_ctx_ty *)spsc_chan_recv(&P.cmd);
}

int
pipeline_work_send(far_job_ty *job)
{
	return spsc_chan_send(&P.work, job);
}

far_job_ty *
pipeline_work_recv(void)
{
	return (far_job_ty *)spsc_chan_recv(&P.work);
}

int
pipeline_done_send(far_result_ty *res)
{
	return spsc_chan_send(&P.done, res);
}

far_result_ty *
pipeline_done_recv(void)
{
	return (far_result_ty *)spsc_chan_recv(&P.done);
}

far_result_ty *
pipeline_done_try_recv(void)
{
	return (far_result_ty *)spsc_chan_try_recv(&P.done);
}

int
pipeline_grep_work_send(far_result_ty *res)
{
	return spsc_chan_send(&P.grep_work, res);
}

far_result_ty *
pipeline_grep_work_recv(void)
{
	return (far_result_ty *)spsc_chan_recv(&P.grep_work);
}

far_result_ty *
pipeline_grep_work_try_recv(void)
{
	return (far_result_ty *)spsc_chan_try_recv(&P.grep_work);
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

int
pipeline_start(void)
{
	if (P.started)
		return 0;
	if (jstr_unlikely(spsc_chan_init(&P.cmd, P.cmd_slots, PIPELINE_CMD_DEPTH) != 0 ||
	                 spsc_chan_init(&P.work, P.work_slots, PIPELINE_DEPTH) != 0 ||
	                 spsc_chan_init(&P.done, P.done_slots, PIPELINE_DEPTH) != 0 ||
	                 spsc_chan_init(&P.ui_cmd, P.ui_cmd_slots, PIPELINE_UI_DEPTH) != 0 ||
	                 spsc_chan_init(&P.ui_ack, P.ui_ack_slots, PIPELINE_UI_DEPTH) != 0 ||
	                 spsc_chan_init(&P.grep_work, P.grep_work_slots, PIPELINE_GREP_WORK_DEPTH) != 0 ||
	                 spsc_chan_init(&P.grep_msg, P.grep_msg_slots, PIPELINE_GREP_MSG_DEPTH) != 0 ||
	                 spsc_chan_init(&P.grep_cfg, P.grep_cfg_slots, PIPELINE_UI_DEPTH) != 0 ||
	                 spsc_chan_init(&P.grep_retire, P.grep_retire_slots, PIPELINE_GREP_RETIRE_DEPTH) != 0))
		return -1;
	if (jstr_unlikely(FAR_THREAD_CREATE(&P.d_thread, grep_worker_thread, NULL) != FAR_THREAD_SUCCESS))
		return -1;
	if (jstr_unlikely(FAR_THREAD_CREATE(&P.c_thread, terminal_ui_thread, NULL) != FAR_THREAD_SUCCESS)) {
		grep_cfg_ty stop;
		stop.kind = GREP_CFG_STOP;
		(void)spsc_chan_send(&P.grep_cfg, &stop);
		FAR_THREAD_JOIN(P.d_thread);
		return -1;
	}
	if (jstr_unlikely(FAR_THREAD_CREATE(&P.b_thread, process_thread, NULL) != FAR_THREAD_SUCCESS)) {
		far_ui_cmd_ty stop;
		stop.kind = FAR_UI_STOP;
		stop.root = NULL;
		(void)spsc_chan_send(&P.ui_cmd, &stop);
		FAR_THREAD_JOIN(P.c_thread);
		return -1;
	}
	if (jstr_unlikely(FAR_THREAD_CREATE(&P.a_thread, traverse_thread, NULL) != FAR_THREAD_SUCCESS)) {
		far_ui_cmd_ty stop;
		stop.kind = FAR_UI_STOP;
		stop.root = NULL;
		(void)spsc_chan_send(&P.ui_cmd, &stop);
		FAR_THREAD_JOIN(P.c_thread);
		(void)spsc_chan_send(&P.work, NULL);
		FAR_THREAD_JOIN(P.b_thread);
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
	grep_cfg_ty gstop;
	gstop.kind = GREP_CFG_STOP;
	(void)spsc_chan_send(&P.grep_cfg, &gstop);
	FAR_THREAD_JOIN(P.d_thread);
	far_ui_cmd_ty stop;
	stop.kind = FAR_UI_STOP;
	stop.root = NULL;
	(void)spsc_chan_send(&P.ui_cmd, &stop);
	FAR_THREAD_JOIN(P.c_thread);
	(void)spsc_chan_send(&P.cmd, NULL);
	FAR_THREAD_JOIN(P.a_thread);
	FAR_THREAD_JOIN(P.b_thread);
	P.ui_live = 0;
	P.started = 0;
}

int
pipeline_run(root_ctx_ty *R root)
{
	if (jstr_unlikely(!P.started) && pipeline_start() != 0)
		return JSTR_RET_ERR;
	atomic_init(&root->cancel, false);
	atomic_init(&root->total, 0);
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
	unsigned long next = 0;
	int canceled = 0;
	int broken = 0;
	int failed = 0;
	int ret = JSTR_RET_SUCC;
	for (;;) {
		far_result_ty *const res = pipeline_done_recv();
		if (jstr_unlikely(!res)) {
			ret = JSTR_RET_ERR;
			break;
		}
		if (res->kind == FAR_RES_EOS) {
			ui_result_free(res);
			ret = atomic_load_explicit(&root->ftw_ret, memory_order_acquire);
			break;
		}
		if (jstr_unlikely(res->seq != next)) {
			broken = 1;
			atomic_store_explicit(&root->cancel, true, memory_order_release);
		}
		if (!canceled && !broken && !res->canceled) {
			if (res->pr.err) {
				if (G.confirm_pass && (G.mode & MODE_CONFIRM)) {
					failed = 1;
					canceled = 1;
					atomic_store_explicit(&root->cancel, true, memory_order_release);
				} else {
					++root->a->err_count;
				}
			} else if (jstr_chk(ui_result(res, root->a))) {
				if (G.confirm_pass && (G.mode & MODE_CONFIRM)) {
					failed = 1;
					canceled = 1;
					atomic_store_explicit(&root->cancel, true, memory_order_release);
				} else {
					++root->a->err_count;
				}
			}
		}
		ui_result_free(res);
		++next;
	}
	root->a->err_count += atomic_load_explicit(&root->prod_errs, memory_order_acquire);
	if (broken || failed)
		return JSTR_RET_ERR;
	return ret;
}
