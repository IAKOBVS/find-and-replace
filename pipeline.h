/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef PIPELINE_H
#define PIPELINE_H

#include "stage.h"

void pipeline_set_workers(size_t count);
size_t pipeline_worker_count(void);
void pipeline_root_set(root_ctx_ty *root);
root_ctx_ty *pipeline_root_get(void);
unsigned long pipeline_root_epoch(void);
int pipeline_stopping(void);
int pipeline_start(void);
void pipeline_shutdown(void);
int pipeline_run(root_ctx_ty *R root);

root_ctx_ty *pipeline_cmd_recv(void);
int pipeline_work_send(far_job_ty *job);
far_job_ty *pipeline_work_try_recv(void);
int pipeline_done_send(size_t worker, far_result_ty *res);
far_result_ty *pipeline_done_try_recv(size_t worker);
int pipeline_grep_work_send(size_t worker, far_result_ty *res);
far_result_ty *pipeline_grep_work_try_recv(size_t worker);
int pipeline_grep_msg_send(far_grep_msg_ty *msg);
far_grep_msg_ty *pipeline_grep_msg_recv(void);
far_grep_msg_ty *pipeline_grep_msg_try_recv(void);
int pipeline_grep_cfg_send(grep_cfg_ty *cfg);
grep_cfg_ty *pipeline_grep_cfg_recv(void);
grep_cfg_ty *pipeline_grep_cfg_try_recv(void);
int pipeline_grep_retire_try_send(grep_lines_ty *lines);
grep_lines_ty *pipeline_grep_retire_try_recv(void);
far_ui_cmd_ty *pipeline_ui_cmd_recv(void);
far_ui_cmd_ty *pipeline_ui_cmd_try_recv(void);
int pipeline_ui_ack_send(int status);
int pipeline_ui_ack_recv(void);
int pipeline_ui_finish(void);

#endif /* PIPELINE_H */
