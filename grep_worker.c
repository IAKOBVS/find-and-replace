/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "grep_worker.h"
#include "pipeline.h"
#include "procfs.h"
#include "ui.h"
#include "spsc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define GREP_BATCH_MAX 64

typedef struct cached_file_ty {
	char *fname;
	size_t fname_len;
	size_t size;
	unsigned int mode;
	jstr_ty content;
	int cached;
} cached_file_ty;

static cached_file_ty *cache;
static size_t cache_size;
static size_t cache_cap;
static size_t cache_bytes;
static size_t cache_max;

typedef struct grep_cfg_state_ty {
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
	jstr_twoway_ty twoway;
	jstr_re_ty regex;
	jstr_re_ty inc_re;
	jstr_re_ty exc_re;
	int have_inc;
	int have_exc;
	int ready;
} grep_cfg_state_ty;

static grep_cfg_state_ty C;
static size_t sent_matches;
static size_t data_seen;
static size_t pending_eos_total;
static int pending_eos;
static grep_line_ty batch[GREP_BATCH_MAX];
static size_t batch_n;
static size_t batch_files;
static unsigned long batch_gen;
static grep_lines_ty *retire_cur;
static size_t retire_at;

static void batch_discard(void);

static void
cfg_clear(void)
{
	free(C.find);
	free(C.files);
	free(C.include);
	free(C.exclude);
	if (C.use_regex)
		jstr_re_free(&C.regex);
	if (C.have_inc)
		jstr_re_free(&C.inc_re);
	if (C.have_exc)
		jstr_re_free(&C.exc_re);
	memset(&C, 0, sizeof C);
}

static void
cfg_compile(grep_cfg_ty *R msg)
{
	batch_discard();
	cfg_clear();
	C.gen = msg->gen;
	C.find = msg->find;
	C.find_len = msg->find_len;
	C.files = msg->files;
	C.files_len = msg->files_len;
	C.include = msg->include;
	C.include_len = msg->include_len;
	C.exclude = msg->exclude;
	C.exclude_len = msg->exclude_len;
	C.limit = msg->limit;
	C.use_regex = msg->use_regex;
	C.cflags = msg->cflags;
	C.eflags = msg->eflags;
	msg->find = NULL;
	msg->files = NULL;
	msg->include = NULL;
	msg->exclude = NULL;
	C.ready = 1;
	if (C.use_regex) {
		if (C.find_len > 0 && jstr_re_comp(&C.regex, C.find, C.cflags) != JSTR_RE_RET_NOERROR)
			C.ready = 0;
	} else {
		jstr_memmem_comp(&C.twoway, C.find, C.find_len);
	}
	if (C.include_len > 0 && jstr_re_comp(&C.inc_re, C.include, C.cflags) == JSTR_RE_RET_NOERROR)
		C.have_inc = 1;
	if (C.exclude_len > 0 && jstr_re_comp(&C.exc_re, C.exclude, C.cflags) == JSTR_RE_RET_NOERROR)
		C.have_exc = 1;
}

static int
cfg_accept(const char *R fname, size_t fname_len)
{
	if (C.files_len > 0 && jstr_strstr_len(fname, fname_len, C.files, C.files_len) == NULL)
		return 0;
	const char *base = jstr_memrchr(fname, '/', fname_len);
	base = (base != NULL && *(base + 1)) ? base + 1 : fname;
	const size_t base_len = (size_t)(fname + fname_len - base);
	if (C.have_inc && jstr_re_match_len(&C.inc_re, base, base_len, 0) != JSTR_RE_RET_NOERROR)
		return 0;
	if (C.have_exc && jstr_re_match_len(&C.exc_re, base, base_len, 0) == JSTR_RE_RET_NOERROR)
		return 0;
	return 1;
}

static void
batch_discard(void)
{
	for (size_t i = 0; i < batch_n; ++i)
		free(batch[i].owner);
	batch_n = 0;
	batch_files = 0;
}

static void
batch_flush(void)
{
	if (batch_n == 0)
		return;
	far_grep_msg_ty *const msg = (far_grep_msg_ty *)calloc(1, sizeof *msg);
	grep_line_ty *const lines = (grep_line_ty *)malloc(batch_n * sizeof *lines);
	if (jstr_unlikely(!msg || !lines)) {
		free(msg);
		free(lines);
		batch_discard();
		return;
	}
	memcpy(lines, batch, batch_n * sizeof *lines);
	msg->kind = FAR_GREP_MATCH;
	msg->gen = batch_gen;
	msg->lines = lines;
	msg->count = batch_n;
	msg->files_matched = batch_files;
	if (pipeline_grep_msg_send(msg) != 0) {
		for (size_t i = 0; i < batch_n; ++i)
			free(batch[i].owner);
		free(lines);
		free(msg);
	}
	batch_n = 0;
	batch_files = 0;
}

static void
send_one_match(const char *R fname, size_t fname_len, size_t line,
               const char *R data, size_t len, size_t moff, size_t mlen, int first)
{
	if (moff > len)
		moff = 0;
	if (mlen > len - moff)
		mlen = len - moff;
	char *const block = (char *)malloc(fname_len + 1 + len + 1);
	if (jstr_unlikely(!block))
		return;
	memcpy(block, fname, fname_len);
	block[fname_len] = '\0';
	memcpy(block + fname_len + 1, data, len);
	block[fname_len + 1 + len] = '\0';
	grep_line_ty *const gl = &batch[batch_n++];
	gl->fname = block;
	gl->fname_len = fname_len;
	gl->line_num = line;
	gl->content = block + fname_len + 1;
	gl->content_len = len;
	gl->match_off = moff;
	gl->match_len = mlen;
	gl->owner = block;
	batch_gen = C.gen;
	if (first)
		++batch_files;
	if (batch_n == GREP_BATCH_MAX)
		batch_flush();
}

static void
scan_content(const char *R fname, size_t fname_len, const jstr_ty *R buf)
{
	if (!C.ready || !cfg_accept(fname, fname_len))
		return;
	const char *d = buf->data;
	const size_t n = buf->size;
	const char *p = d;
	int first = 1;
	for (size_t line = 1;; ++line) {
		const char *nl = (const char *)memchr(p, '\n', (size_t)(d + n - p));
		const size_t line_len = (nl != NULL) ? (size_t)(nl - p) : (size_t)(d + n - p);
		const char *const line_data = line_len ? p : "";
		int matched = 0;
		size_t moff = 0;
		size_t mlen = 0;
		if (C.find_len == 0) {
			matched = 1;
		} else if (C.use_regex) {
			regmatch_t rm = { 0 };
			matched = (jstr_re_search_len(&C.regex, line_data, line_len, &rm, C.eflags) == JSTR_RE_RET_NOERROR);
			if (matched) {
				moff = (size_t)rm.rm_so;
				mlen = (size_t)(rm.rm_eo - rm.rm_so);
			}
		} else {
			const char *hit = (const char *)jstr_memmem_exec(&C.twoway, p, line_len, C.find, C.find_len);
			if (hit != NULL) {
				matched = 1;
				moff = (size_t)(hit - p);
				mlen = C.find_len;
			}
		}
		if (matched) {
			if (sent_matches >= C.limit)
				return;
			send_one_match(fname, fname_len, line, line_data, line_len, moff, mlen, first);
			++sent_matches;
			first = 0;
			if (C.limit != (size_t)-1)
				batch_flush();
		}
		if (nl == NULL)
			break;
		p = nl + 1;
	}
}

static void
send_kind(far_grep_msg_kind_ty kind)
{
	batch_flush();
	far_grep_msg_ty *const msg = (far_grep_msg_ty *)calloc(1, sizeof *msg);
	if (jstr_unlikely(!msg))
		return;
	msg->kind = kind;
	msg->gen = C.gen;
	if (pipeline_grep_msg_send(msg) != 0)
		free(msg);
}

static void
rescan_all(int full)
{
	sent_matches = 0;
	batch_discard();
	for (size_t i = 0; i < cache_size; ++i) {
		cached_file_ty *const file = &cache[i];
		if (file->cached) {
			scan_content(file->fname, file->fname_len, &file->content);
			continue;
		}
		jstr_ty tmp = (jstr_ty)JSTR_INIT;
		if (jstr_chk(jstr_reserve_j(&tmp, file->size)) ||
		    jstr_chk(jstr_io_readfile_len_j(&tmp, file->fname, 0, file->size))) {
			jstr_free_j(&tmp);
			continue;
		}
		scan_content(file->fname, file->fname_len, &tmp);
		jstr_free_j(&tmp);
	}
	(void)full;
	send_kind(FAR_GREP_DONE);
}

static cached_file_ty *
cache_add(const char *R fname, size_t fname_len, size_t size, unsigned int mode, jstr_ty *R content)
{
	if (cache_size >= cache_cap) {
		cache_cap = cache_cap == 0 ? 32 : cache_cap * 2;
		cached_file_ty *const tmp = (cached_file_ty *)realloc(cache, cache_cap * sizeof *tmp);
		if (jstr_unlikely(!tmp))
			jstr_errdie("%s", "Out of memory.\n");
		cache = tmp;
	}
	cached_file_ty *const file = &cache[cache_size++];
	memset(file, 0, sizeof *file);
	file->fname = (char *)malloc(fname_len + 1);
	if (jstr_unlikely(!file->fname))
		jstr_errdie("%s", "Out of memory.\n");
	memcpy(file->fname, fname, fname_len);
	file->fname[fname_len] = '\0';
	file->fname_len = fname_len;
	file->size = size;
	file->mode = mode;
	file->content = (jstr_ty)JSTR_INIT;
	if (cache_bytes + content->size <= cache_max) {
		file->content = *content;
		*content = (jstr_ty)JSTR_INIT;
		file->cached = 1;
		cache_bytes += file->content.size;
	}
	return file;
}

static void
handle_result(far_result_ty *R res)
{
	if (res->kind == FAR_RES_EOS) {
		pending_eos = 1;
		pending_eos_total = res->total;
		ui_result_free(res);
		if (data_seen >= pending_eos_total) {
			send_kind(FAR_GREP_EOS);
			pending_eos = 0;
			data_seen = 0;
		}
		return;
	}
	++data_seen;
	if (res->pr.err) {
		send_kind(FAR_GREP_ERROR);
		ui_result_free(res);
		return;
	}
	if (res->pr.out == NULL) {
		ui_result_free(res);
		return;
	}
	cached_file_ty *const file = cache_add(res->path, res->path_len,
	                                       (size_t)res->pr.st.st_size, res->pr.st.st_mode,
	                                       res->pr.out);
	scan_content(file->fname, file->fname_len, file->cached ? &file->content : res->pr.out);
	ui_result_free(res);
}

static void
retire_free_all(grep_lines_ty *lines)
{
	for (size_t i = 0; i < lines->size; ++i)
		free(lines->data[i].owner);
	free(lines->data);
	free(lines);
}

static int
retire_step(void)
{
	if (retire_cur == NULL) {
		retire_cur = pipeline_grep_retire_try_recv();
		retire_at = 0;
		if (retire_cur == NULL)
			return 0;
	}
	const size_t end = JSTR_MIN(retire_cur->size, retire_at + 4096);
	for (size_t i = retire_at; i < end; ++i)
		free(retire_cur->data[i].owner);
	retire_at = end;
	if (retire_at >= retire_cur->size) {
		free(retire_cur->data);
		free(retire_cur);
		retire_cur = NULL;
	}
	return 1;
}

far_thread_ret_ty
grep_worker_thread(void *arg)
{
	(void)arg;
	cache_max = procfs_mem_available() / 2;
	unsigned int spin = 0;
	for (;;) {
		int did = 0;
		grep_cfg_ty *cfg;
		while ((cfg = pipeline_grep_cfg_try_recv()) != NULL) {
			const int full = cfg->kind == GREP_CFG_FULL;
			const int stop = cfg->kind == GREP_CFG_STOP;
			if (stop)
				goto out;
			cfg_compile(cfg);
			free(cfg);
			rescan_all(full);
			did = 1;
		}
		if (retire_step())
			did = 1;
		for (size_t w = 0; w < pipeline_worker_count(); ++w) {
			far_result_ty *res;
			while ((res = pipeline_grep_work_try_recv(w)) != NULL) {
				handle_result(res);
				did = 1;
			}
		}
		if (pending_eos && data_seen >= pending_eos_total) {
			send_kind(FAR_GREP_EOS);
			pending_eos = 0;
			data_seen = 0;
			did = 1;
		}
		if (did)
			spin = 0;
		else
			spsc_backoff(&spin);
	}
out:
	if (retire_cur != NULL)
		retire_free_all(retire_cur);
	batch_discard();
	for (size_t i = 0; i < cache_size; ++i) {
		free(cache[i].fname);
		jstr_free_j(&cache[i].content);
	}
	free(cache);
	cfg_clear();
	return FAR_THREAD_RETURN;
}
