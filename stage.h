/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef STAGE_H
#define STAGE_H

#include "common.h"

#include <stdalign.h>
#include <stdatomic.h>

/* Per-root traversal/process/UI context. */
typedef struct args_ty {
	const char *find;
	size_t find_len;
	const char *rplc;
	size_t rplc_len;
	const jstr_twoway_ty *t;
	size_t err_count;
} args_ty;

/* Payload produced by the process stage for one file. */
typedef struct process_result_ty {
	jstr_ty *out;
	struct stat st;
	size_t changed;
	int report;
	int matched;
	int err;
} process_result_ty;

typedef enum {
	FAR_ROOT_DIR,
	FAR_ROOT_FILE,
	FAR_ROOT_STDIN,
	FAR_ROOT_MEM
} far_root_kind_ty;

typedef enum {
	FAR_JOB_FILE,
	FAR_JOB_STDIN,
	FAR_JOB_MEM,
	FAR_JOB_EOS
} far_job_kind_ty;

typedef enum {
	FAR_RES_DATA,
	FAR_RES_EOS
} far_res_kind_ty;

typedef enum {
	FAR_UI_ROOT,
	FAR_UI_END,
	FAR_UI_STOP
} far_ui_cmd_kind_ty;

typedef enum {
	FAR_GREP_MATCH,
	FAR_GREP_EOS,
	FAR_GREP_DONE,
	FAR_GREP_ERROR
} far_grep_msg_kind_ty;

typedef struct far_grep_msg_ty {
	far_grep_msg_kind_ty kind;
	unsigned long gen;
	grep_line_ty *lines;
	size_t count;
	size_t files_matched;
} far_grep_msg_ty;

typedef enum {
	GREP_CFG_UPDATE,
	GREP_CFG_FULL,
	GREP_CFG_STOP
} grep_cfg_kind_ty;

typedef struct grep_cfg_ty {
	grep_cfg_kind_ty kind;
	unsigned long gen;
	char *find;
	size_t find_len;
	char *files;
	size_t files_len;
	char *include;
	size_t include_len;
	char *exclude;
	size_t exclude_len;
	size_t limit;
	int use_regex;
	int cflags;
	int eflags;
} grep_cfg_ty;

typedef struct far_job_ty far_job_ty;
typedef struct far_result_ty far_result_ty;
typedef struct root_ctx_ty root_ctx_ty;

struct far_job_ty {
	unsigned long seq;
	far_job_kind_ty kind;
	char *path;
	size_t path_len;
	struct stat st;
	root_ctx_ty *root;
	const file_ty *mem_file;
};

struct far_result_ty {
	unsigned long seq;
	far_res_kind_ty kind;
	char *path;
	size_t path_len;
	int canceled;
	process_result_ty pr;
};

typedef struct far_ui_cmd_ty {
	far_ui_cmd_kind_ty kind;
	root_ctx_ty *root;
} far_ui_cmd_ty;

struct root_ctx_ty {
	far_root_kind_ty kind;
	const char *path;
	struct stat st;
	const file_ty *const *mem_files;
	size_t mem_count;
	args_ty *a;
	jstr_twoway_ty *t;
	atomic_bool cancel;
	atomic_size_t total;
	atomic_int ftw_ret;
	atomic_size_t prod_errs;
	unsigned long seq;
	far_job_ty eos;
};

#endif /* STAGE_H */
