/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "traverse.h"
#include "process.h"
#include "pipeline.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static int
traverse_emit(root_ctx_ty *R root, const char *R path, size_t path_len,
              const struct stat *st, far_job_kind_ty kind, const file_ty *mem_file)
{
	far_job_ty *job = NULL;
	int ret = JSTR_RET_ERR;
	if (jstr_unlikely(atomic_load_explicit(&root->cancel, memory_order_acquire)))
		return JSTR_RET_ERR;
	job = (far_job_ty *)malloc(sizeof *job);
	if (jstr_unlikely(!job)) {
		atomic_fetch_add_explicit(&root->prod_errs, 1, memory_order_relaxed);
		return JSTR_RET_SUCC;
	}
	job->path = NULL;
	if (path != NULL) {
		job->path = (char *)malloc(path_len + 1);
		if (jstr_unlikely(!job->path)) {
			atomic_fetch_add_explicit(&root->prod_errs, 1, memory_order_relaxed);
			ret = JSTR_RET_SUCC;
			goto out;
		}
		memcpy(job->path, path, path_len);
		job->path[path_len] = '\0';
	}
	job->path_len = path_len;
	job->st = *st;
	job->kind = kind;
	job->root = root;
	job->mem_file = mem_file;
	job->seq = root->seq;
	if (jstr_unlikely(pipeline_work_send(job) != 0))
		goto out;
	++root->seq;
	ret = JSTR_RET_SUCC;
	job = NULL;
out:
	if (job != NULL) {
		free(job->path);
		free(job);
	}
	return ret;
}

static JSTR_IO_FTW_FUNC(traverse_enqueue, ftw, args)
{
	root_ctx_ty *const root = (root_ctx_ty *)(void *)args;
	return traverse_emit(root, ftw->dirpath, (size_t)ftw->dirpath_len,
	                     ftw->st, FAR_JOB_FILE, NULL);
}

far_thread_ret_ty
traverse_thread(void *arg)
{
	(void)arg;
	for (;;) {
		root_ctx_ty *const root = (root_ctx_ty *)pipeline_cmd_recv();
		if (root == NULL)
			break;
		atomic_store_explicit(&root->cancel, false, memory_order_relaxed);
		atomic_store_explicit(&root->total, 0, memory_order_relaxed);
		atomic_store_explicit(&root->ftw_ret, JSTR_RET_SUCC, memory_order_relaxed);
		atomic_store_explicit(&root->prod_errs, 0, memory_order_relaxed);
		root->seq = 0;
		int ret = JSTR_RET_SUCC;
		switch (root->kind) {
		case FAR_ROOT_DIR:
			ret = jstr_io_ftw(root->path, traverse_enqueue, root,
			                  JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG,
			                  (G.have_include || G.have_exclude) ? matcher : NULL,
			                  NULL);
			break;
		case FAR_ROOT_FILE:
			ret = traverse_emit(root, root->path, strlen(root->path), &root->st, FAR_JOB_FILE, NULL);
			break;
		case FAR_ROOT_STDIN: {
			struct stat st;
			memset(&st, 0, sizeof st);
			ret = traverse_emit(root, NULL, 0, &st, FAR_JOB_STDIN, NULL);
			break;
		}
		case FAR_ROOT_MEM:
			for (size_t i = 0; i < root->mem_count; ++i) {
				const file_ty *const file = root->mem_files[i];
				struct stat st;
				memset(&st, 0, sizeof st);
				st.st_mode = file->st_mode;
				st.st_size = (off_t)file->content_size;
				ret = traverse_emit(root, file->fname, file->fname_len, &st, FAR_JOB_MEM, file);
				if (ret != JSTR_RET_SUCC)
					break;
			}
			break;
		}
		atomic_store_explicit(&root->total, root->seq, memory_order_release);
		atomic_store_explicit(&root->ftw_ret, ret, memory_order_release);
		root->eos.seq = root->seq;
		root->eos.kind = FAR_JOB_EOS;
		root->eos.path = NULL;
		root->eos.path_len = 0;
		root->eos.root = root;
		root->eos.mem_file = NULL;
		memset(&root->eos.st, 0, sizeof root->eos.st);
		if (jstr_unlikely(pipeline_work_send(&root->eos) != 0))
			atomic_fetch_add_explicit(&root->prod_errs, 1, memory_order_relaxed);
	}
	(void)pipeline_work_send(NULL);
	return FAR_THREAD_RETURN;
}

JSTR_IO_FTW_FUNC_MATCH(matcher, fname, fname_len, args)
{
	if (G.have_include)
		if (jstr_re_match_len(&G.include_re, fname, fname_len, 0) != JSTR_RE_RET_NOERROR)
			return 1;
	if (G.have_exclude)
		if (jstr_re_match_len(&G.exclude_re, fname, fname_len, 0) == JSTR_RE_RET_NOERROR)
			return 1;
	return 0;
	(void)args;
}
