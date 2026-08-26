/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "pipeline.h"
#include "process.h"
#include "async.h"

#include <stdlib.h>
#include <string.h>

/* Threaded recursive pipeline, expressed entirely through the async
 * substrate (async.h): one traversal thread walks the tree and SENDs jobs
 * into a bounded work channel; N processing threads recv a job, process it
 * with private buffers, and SEND the finished job into a done channel; the
 * calling thread is the UI/emitter — it owns every byte written to stdout
 * and stderr and releases results strictly in traversal order by holding
 * out-of-order completions until their turn. No other thread touches stdio,
 * G counters, or exit().
 *
 * Channels bound memory: at most PIPELINE_DEPTH jobs exist at once (work_ch
 * capacity), so payload buffers held for unemitted results are capped too.
 * Buffer shells recycle through buf_ch; workers pop a pair per job and the
 * emitter always pushes the pair back after receiving it, emitted or not.
 * Shutdown: the producer closes work_ch after ftw; workers then drain and
 * each send a NULL sentinel on done_ch before exiting; the emitter stops
 * once it has all sentinels and nothing buffered. A fatal job error makes
 * the emitter close work_ch (releasing a blocked producer), skip remaining
 * output, and keep draining until everyone is home — mirroring sequential's
 * die-on-first-fatal while staying deadlock-free. */

#define PIPELINE_DEPTH 64

/* Collect mode: file is binary, cache it as absent. */
#define PIPELINE_F_SKIP 4

typedef struct job_ty {
	unsigned long seq;
	char path[JSTR_IO_PATH_MAX];
	size_t path_len;
	struct stat st;
	/* Counted failure without a message: mirrors callback_file's
	 * ++err_count in the sequential walk. */
	int err;
	/* Fatal message rendered by the worker; pe.set decides. */
	proc_err_ty pe;
	/* Printable payload (replaced content / formatted grep lines) plus the
	 * second recycled shell; both return to buf_ch after emit. */
	jstr_ty *out;
	jstr_ty *scratch;
	int flags;
} job_ty;

/* Shared context handed to the pool threads and read-only from there on. */
typedef struct pipe_ctx_ty {
	args_ty *a;
	const char *dir;
	async_chan_ty *work_ch;
	async_chan_ty *done_ch;
	async_chan_ty *buf_ch;
	/* Producer-private result, read by main only after joining it. */
	jstr_ret_ty ftw_ret;
	size_t prod_errs;
	/* Traversal-order sequence for the next job; written only by the
	 * producer thread, read by workers/emitter through channel ordering. */
	unsigned long next_seq;
	/* 1 = collect mode: workers only read files; the emitter caches them. */
	int collect;
} pipe_ctx_ty;

/* ftw matcher passthrough (--include/--exclude basename regexes). */
JSTR_IO_FTW_FUNC_MATCH(traverse_match, fname, fname_len, args)
{
	return matcher(fname, fname_len, args);
}

/* Traversal thread: ftw callback enqueues one job per regular file. */
JSTR_IO_FTW_FUNC(traverse_callback, ftw, args)
{
	pipe_ctx_ty *const ctx = (pipe_ctx_ty *)(void *)args;
	job_ty *job = (job_ty *)malloc(sizeof(*job));
	if (jstr_unlikely(job == NULL)) {
		++ctx->prod_errs;
		return JSTR_RET_SUCC;
	}
	job->seq = ctx->next_seq++;
	memcpy(job->path, ftw->dirpath, (size_t)ftw->dirpath_len);
	job->path[(size_t)ftw->dirpath_len] = '\0';
	job->path_len = (size_t)ftw->dirpath_len;
	job->st = *ftw->st;
	job->err = 0;
	job->pe.set = 0;
	job->flags = 0;
	if (jstr_unlikely(async_chan_send(ctx->work_ch, job) != 0)) {
		free(job);
		return JSTR_RET_ERR;
	}
	return JSTR_RET_SUCC;
}

static void *
producer_main(void *arg)
{
	pipe_ctx_ty *const ctx = (pipe_ctx_ty *)(void *)arg;
	ctx->ftw_ret = jstr_io_ftw(ctx->dir, traverse_callback, ctx, JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG,
	                           ((G.gflags & (F_HAVE_INCLUDE | F_HAVE_EXCLUDE))) ? traverse_match : NULL, ctx);
	async_chan_close(ctx->work_ch);
	return NULL;
}

/* Processing thread: pull jobs until the channel closes. Never touches
 * stdio and never exits; failures travel inside the job.
 *
 * A pair of buffer shells is acquired BEFORE taking the job: the shells of
 * out-of-order results are only recycled when the emitter reaches their
 * sequence, so a worker that grabbed a job first could wait for buffers
 * attached to results waiting on that very job -- hold-and-wait deadlock.
 * Waiting for buffers empty-handed breaks the cycle. */
static void *
worker_main(void *arg)
{
	pipe_ctx_ty *const ctx = (pipe_ctx_ty *)(void *)arg;
	const jstr_twoway_ty *const t = ctx->a->t;
	jstr_ty *cbuf;
	jstr_ty *obuf;
	job_ty *job;
	jstr_ret_ty ret = JSTR_RET_SUCC;
	for (;;) {
		cbuf = (jstr_ty *)async_chan_recv(ctx->buf_ch);
		obuf = (jstr_ty *)async_chan_recv(ctx->buf_ch);
		job = (job_ty *)async_chan_recv(ctx->work_ch);
		if (job == NULL) {
			async_chan_send(ctx->buf_ch, cbuf);
			async_chan_send(ctx->buf_ch, obuf);
			break;
		}
		jstr_empty_j(cbuf);
		jstr_empty_j(obuf);
		job->out = obuf;
		job->scratch = cbuf;
		if (ctx->collect) {
			const int rr = pipeline_read_file(cbuf, job->path, job->path_len, &job->st);
			if (rr == PIPELINE_READ_ERR)
				job->err = 1;
			else if (rr == PIPELINE_READ_BINARY)
				job->flags |= PIPELINE_F_SKIP;
			else {
				/* Hand the loaded content to the emitter: swap shells so
				 * both keep their allocations for reuse. */
				jstr_ty tmp = *obuf;
				*obuf = *cbuf;
				*cbuf = tmp;
			}
		} else {
			ret = pipeline_process_file(t, cbuf, job->path, job->path_len, &job->st,
			                            ctx->a->find, ctx->a->find_len,
			                            ctx->a->rplc, ctx->a->rplc_len,
			                            &job->pe, obuf, &job->flags);
			if (ret != JSTR_RET_SUCC && !job->pe.set)
				job->err = 1;
		}
		async_chan_send(ctx->done_ch, job);
	}
	async_chan_send(ctx->done_ch, NULL);
	return NULL;
}

/* Task adapters: pool tasks return void; the thread bodies' returns are
 * meaningless (results travel through channels). */
static void worker_task(void *R arg);
static void *producer_thread(void *R arg);

/* Emit one job on the UI thread: stdout/stderr writes happen here and only
 * here, in strict traversal order. Returns nonzero for a fatal error. */
static int
emit_job(args_ty *R a, const job_ty *R job)
{
	if (job->pe.set) {
		(void)fwrite(job->pe.buf, 1, strlen(job->pe.buf), stderr);
		(void)fflush(stderr);
		return 1;
	}
	if (job->err) {
		++a->err_count;
		return 0;
	}
	if ((G.mode & MODE_GREP) && (job->flags & PIPELINE_F_MATCHED))
		G.gflags |= F_GREP_MATCHED;
	if (job->out != NULL && job->out->size > 0)
		if (jstr_unlikely(fwrite(job->out->data, 1, job->out->size, stdout) != job->out->size))
			++a->err_count;
	if (job->flags & PIPELINE_F_CHANGED)
		if (jstr_chk(report_changed_file(job->path, job->path_len)))
			++a->err_count;
	return 0;
}

/* Insert into the small out-of-order buffer sorted by seq (linear; at most
 * PIPELINE_DEPTH entries ever wait here). Returns the new size. */
static size_t
hold_insert(job_ty **held, size_t n, job_ty *job)
{
	size_t k = 0;
	while (k < n && held[k]->seq < job->seq)
		++k;
	memmove(held + k + 1, held + k, (n - k) * sizeof(*held));
	held[k] = job;
	return n + 1;
}

static jstr_ret_ty
pipeline_run(const char *R dir, args_ty *R a, size_t nwork, int *fatal_out, int collect);

static void
worker_task(void *R arg)
{
	(void)worker_main(arg);
}



static void *
producer_thread(void *R arg)
{
	(void)producer_main(arg);
	return NULL;
}

jstr_ret_ty
pipeline_run_dir(const char *R dir, args_ty *R a, size_t nwork, int *fatal_out)
{
	return pipeline_run(dir, a, nwork, fatal_out, 0);
}

jstr_ret_ty
pipeline_collect_dir(const char *R dir, args_ty *R a, size_t nwork)
{
	int fatal = 0;
	const jstr_ret_ty ret = pipeline_run(dir, a, nwork, &fatal, 1);
	if (jstr_unlikely(fatal))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return ret;
}

static jstr_ret_ty
pipeline_run(const char *R dir, args_ty *R a, size_t nwork, int *fatal_out, int collect)
{
	pipe_ctx_ty ctx;
	async_chan_ty *work_ch;
	async_chan_ty *done_ch;
	async_chan_ty *buf_ch;
	job_ty **held;
	unsigned long next_seq;
	size_t nheld;
	size_t eof_seen;
	int fatal;

	*fatal_out = 0;
	nwork = (nwork == 0) ? 1 : nwork;
	if (nwork > PIPELINE_DEPTH)
		nwork = PIPELINE_DEPTH;

	ctx.a = a;
	ctx.dir = dir;
	ctx.ftw_ret = JSTR_RET_SUCC;
	ctx.prod_errs = 0;
	ctx.next_seq = 0;
	ctx.collect = collect;

	work_ch = async_chan_new(PIPELINE_DEPTH);
	done_ch = async_chan_new(PIPELINE_DEPTH + PIPELINE_DEPTH);
	buf_ch = async_chan_new(PIPELINE_DEPTH * 2);
	if (jstr_unlikely(work_ch == NULL || done_ch == NULL || buf_ch == NULL)) {
		async_chan_free(work_ch);
		async_chan_free(done_ch);
		async_chan_free(buf_ch);
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	/* Prefill the buffer pool: two shells per in-flight job. */
	for (size_t k = 0; k < PIPELINE_DEPTH * 2; ++k) {
		jstr_ty *b = (jstr_ty *)malloc(sizeof(*b));
		DIE_IF(b == NULL, "%s", "Out of memory.\n");
		*b = (jstr_ty)JSTR_INIT;
		async_chan_send(buf_ch, b);
	}
	ctx.work_ch = work_ch;
	ctx.done_ch = done_ch;
	ctx.buf_ch = buf_ch;

	/* The pool is process-lifetime (async.h): one traversal task plus N
	 * processing tasks are submitted per directory run; the threads
	 * themselves never exit until async_pool_stop() at process end. */
	if (jstr_unlikely(async_pool_size() == 0))
		DIE_IF(async_pool_start(nwork + 1) != 0, "%s", "Can't start the worker thread pool.\n");
	for (size_t k = 0; k < nwork; ++k)
		async_pool_submit(worker_task, &ctx);
	/* Traversal runs on its own thread: pool slots are all occupied by
	 * workers that block until the walk feeds them, so queueing the
	 * producer behind them would deadlock. */
	async_thread_ty *const producer = async_thread_run(producer_thread, &ctx);
	DIE_IF(producer == NULL, "%s", "Can't start the traversal thread.\n");

	/* Emitter loop (UI thread). */
	held = (job_ty **)malloc((PIPELINE_DEPTH + nwork) * sizeof(*held));
	DIE_IF(held == NULL, "%s", "Out of memory.\n");
	next_seq = 0;
	nheld = 0;
	eof_seen = 0;
	fatal = 0;
	while (!(eof_seen == nwork && nheld == 0)) {
		job_ty *job = (job_ty *)async_chan_recv(done_ch);
		if (job == NULL) {
			++eof_seen;
			continue;
		}
		nheld = hold_insert(held, nheld, job);
		while (nheld > 0 && held[0]->seq == next_seq) {
			job = held[0];
			--nheld;
			memmove(held, held + 1, nheld * sizeof(*held));
			if (collect) {
				if (job->err)
					++a->err_count;
				else if (!(job->flags & PIPELINE_F_SKIP))
					file_pushback(&G.files, job->path, job->path_len, &job->st, job->out);
			} else if (!fatal)
				fatal = emit_job(a, job);
			/* Emit reads the shells above; only then recycle them so
			 * no worker can empty a buffer mid-fwrite. NULL shells
			 * (unreachable defensive path) must not poison the pool. */
			if (job->scratch != NULL)
				async_chan_send(buf_ch, job->scratch);
			if (job->out != NULL)
				async_chan_send(buf_ch, job->out);
			free(job);
			++next_seq;
		}
		if (fatal)
			async_chan_close(work_ch);
	}
	free(held);

	async_pool_barrier();
	async_thread_join(producer);
	a->err_count += ctx.prod_errs;
	*fatal_out = fatal;

	async_chan_free(work_ch);
	async_chan_free(done_ch);
	async_chan_free(buf_ch);

	if (fatal)
		return JSTR_RET_SUCC;
	return ctx.ftw_ret;
}

/* ---------------------------------------------------------------------------
 * STREAMING GREP ENGINE
 *
 * The tty --grep TUI must open instantly on huge trees and must NOT cache
 * file contents. Instead, traversal + pool readers scan every file AS IT IS
 * LOADED and emit only match records (line bytes copied into per-file
 * arenas, width-capped). An orderer thread restores traversal order; the UI
 * thread polls finished batches and renders live progress. Editing the find
 * or the filters bumps the generation: stale in-flight work is discarded
 * without I/O and the tree is simply walked again (search never modifies
 * files, so re-reading is safe).
 * ------------------------------------------------------------------------- */

#include <signal.h>

#define GS_PER_FILE_RECORDS 100000u
#define GS_PER_FILE_ARENA   (32u * JSTR_IO_MIB)

/* Immutable search scope for one generation: pattern, compiled matchers and
 * filter copies. Versions are never mutated after publish, so workers can
 * hold the pointer without locks (they re-read it per file under cfg_mu). */
typedef struct gs_version_ty {
	unsigned long gen;
	char *find;
	size_t find_len;
	int want_regex;
	int eflags;
	jstr_twoway_ty tw;
	jstr_re_ty re;
	int have_inc;
	int have_exc;
	jstr_re_ty inc;
	jstr_re_ty exc;
	char *fsub;
	size_t fsub_n;
	struct gs_version_ty *next;
} gs_version_ty;

struct grep_stream_ty {
	async_lock_ty *cfg_mu;
	async_event_ty *restart;
	unsigned long gen;
	gs_version_ty *versions;
	const char **dirs;
	size_t ndirs;
	size_t dir_cursor;

	async_chan_ty *work_ch;
	async_chan_ty *done_ch;
	async_chan_ty *buf_ch;
	async_thread_ty *producer;
	async_thread_ty *orderer;
	int stop;

	async_lock_ty *out_mu;
	grep_line_ty *staged;
	size_t staged_n;
	size_t staged_cap;
	char **staged_names;
	size_t sn;
	size_t scap;
	char **staged_arenas;
	size_t an;
	size_t acap;
	unsigned long long matches_total;
	unsigned long files_enqueued;
	unsigned long files_done;
	int done;
};

typedef struct sjob_ty {
	unsigned long seq;
	unsigned long gen;
	char path[JSTR_IO_PATH_MAX];
	size_t path_len;
	struct stat st;
	/* result payload */
	char *name;
	grep_line_ty *recs;
	size_t nrecs;
	char *arena;
	size_t arena_used;
	size_t arena_cap;
	unsigned long long overflow;
	int skip;   /* 1 = unreadable/binary/filtered, 2 = end-of-generation */
} sjob_ty;

static size_t
gs_nwork(size_t nwork)
{
	if (nwork == 0)
		nwork = 1;
	if (nwork > PIPELINE_DEPTH)
		nwork = PIPELINE_DEPTH;
	return nwork;
}

/* Basename filter equivalent to interactive_file_pass, evaluated inside
 * reader tasks against the immutable version snapshot. */
static int
gs_filter_pass(const gs_version_ty *R v, const char *R path, size_t path_len)
{
	const char *base = jstr_memrchr(path, '/', path_len);
	base = (base != NULL && *(base + 1)) ? base + 1 : path;
	const size_t base_len = (size_t)(path + path_len - base);
	if (v->fsub_n > 0) {
		if (jstr_strstr_len(path, path_len, v->fsub, v->fsub_n) == NULL)
			return 0;
	}
	if (v->have_inc)
		if (jstr_re_match_len(&v->inc, base, base_len, 0) != JSTR_RE_RET_NOERROR)
			return 0;
	if (v->have_exc)
		if (jstr_re_match_len(&v->exc, base, base_len, 0) == JSTR_RE_RET_NOERROR)
			return 0;
	return 1;
}

/* Append one matching line to the job's capped arena + record list. */
static void
gs_emit(sjob_ty *R job, size_t line_no, const char *R ls, size_t line_len,
        size_t moff, size_t mlen)
{
	const size_t need = line_len;
	job->overflow++;
	if (job->nrecs >= GS_PER_FILE_RECORDS || job->arena_used + need > GS_PER_FILE_ARENA)
		return;
	if (job->arena_used + need > job->arena_cap) {
		size_t ncap = job->arena_cap ? job->arena_cap * 2 : 4096;
		while (ncap < job->arena_used + need)
			ncap *= 2;
		char *const na = (char *)realloc(job->arena, ncap);
		if (jstr_unlikely(na == NULL))
			return;
		job->arena = na;
		job->arena_cap = ncap;
	}
	if (job->nrecs % 64 == 0) {
		const size_t nrc = job->nrecs + 64;
		grep_line_ty *const nr = (grep_line_ty *)realloc(job->recs, nrc * sizeof(*nr));
		if (jstr_unlikely(nr == NULL))
			return;
		job->recs = nr;
	}
	memcpy(job->arena + job->arena_used, ls, need);
	grep_line_ty *const r = &job->recs[job->nrecs++];
	r->fname = job->name;
	r->fname_len = job->path_len;
	r->line_num = line_no;
	r->content = job->arena + job->arena_used;
	r->content_len = need;
	r->match_off = moff;
	r->match_len = mlen;
	job->overflow--;
	job->arena_used += need;
}

/* Fixed-string scan of the whole buffer (one Two-Way pass; per-hit line
 * derivation identical to process.c's iterator). */
static void
gs_scan_fixed(const gs_version_ty *R v, sjob_ty *R job, const char *R d, size_t n)
{
	const char *const end = d + n;
	const char *p = d;
	const char *line_start = d;
	size_t line = 1;
	for (;;) {
		const char *hit;
		const char *le;
		const char *ls;
		if (p >= end)
			break;
		if (v->find_len == 0) {
			/* grep '' semantics: every line matches. */
			hit = p;
		} else {
			hit = (const char *)jstr_memmem_exec(&v->tw, p, (size_t)(end - p), v->find, v->find_len);
			if (hit == NULL)
				break;
			if (memchr(hit, '\n', v->find_len) != NULL) {
				p = hit + 1;
				continue;
			}
		}
		ls = line_start;
		for (;;) {
			const char *nl = (const char *)memchr(ls, '\n', (size_t)(hit - ls));
			if (nl == NULL)
				break;
			ls = nl + 1;
			++line;
		}
		line_start = ls;
		le = (const char *)memchr(hit, '\n', (size_t)(end - hit));
		le = (le != NULL) ? le : end;
		gs_emit(job, line, line_start, (size_t)(le - line_start),
		        (size_t)(hit - line_start), (v->find_len != 0) ? v->find_len : (size_t)(le - hit));
		p = (le < end) ? le + 1 : end;
	}
}

/* Regex scan: per-line to preserve anchor semantics. */
static void
gs_scan_regex(const gs_version_ty *R v, sjob_ty *R job, const char *R d, size_t n)
{
	const char *p = d;
	const char *const end = d + n;
	for (size_t line = 1; p < end; ++line) {
		const char *nl = (const char *)memchr(p, '\n', (size_t)(end - p));
		const size_t line_len = (nl != NULL) ? (size_t)(nl - p) : (size_t)(end - p);
		regmatch_t rm = { 0 };
		if (jstr_re_search_len(&v->re, p, line_len, &rm, v->eflags) == JSTR_RE_RET_NOERROR)
			gs_emit(job, line, p, line_len, (size_t)rm.rm_so, (size_t)(rm.rm_eo - rm.rm_so));
		if (nl == NULL)
			break;
		p = nl + 1;
	}
}

static void
gs_job_free(sjob_ty *R job)
{
	free(job->recs);
	free(job->arena);
	free(job->name);
	free(job);
}

/* Reader task on the persistent pool. Shells are acquired before jobs (the
 * hold-and-wait rule); contents are transient -- nothing is cached. */
static void
gs_worker_task(void *R arg)
{
	grep_stream_ty *const s = (grep_stream_ty *)(void *)arg;
	for (;;) {
		jstr_ty *const cbuf = (jstr_ty *)async_chan_recv(s->buf_ch);
		if (cbuf == NULL)
			break;
		sjob_ty *const job = (sjob_ty *)async_chan_recv(s->work_ch);
		if (job == NULL) {
			async_chan_send(s->buf_ch, cbuf);
			break;
		}
		async_lock_lock(s->cfg_mu);
		gs_version_ty *const v = s->versions; /* newest */
		const unsigned long gen = s->gen;
		async_lock_unlock(s->cfg_mu);

		if (job->gen != gen) {
			job->skip = 1; /* stale generation: discard without I/O */
		} else if (v->find_len == 0) {
			/* Empty FIND: legacy grep parity -- count the file, emit no
			 * lines. Also keeps workers away from the never-compiled
			 * empty-pattern matcher (both Two-Way and regex). */
			job->skip = 1;
		} else if (!gs_filter_pass(v, job->path, job->path_len)) {
			job->skip = 1;
		} else {
			const int rr = pipeline_read_file(cbuf, job->path, job->path_len, &job->st);
			if (rr != PIPELINE_READ_OK) {
				job->skip = 1;
			} else {
				job->name = (char *)malloc(job->path_len + 1);
				if (jstr_unlikely(job->name == NULL)) {
					job->skip = 1;
				} else {
					memcpy(job->name, job->path, job->path_len);
					job->name[job->path_len] = '\0';
					if (v->want_regex)
						gs_scan_regex(v, job, cbuf->data, cbuf->size);
					else
						gs_scan_fixed(v, job, cbuf->data, cbuf->size);
				}
			}
		}
		async_chan_send(s->buf_ch, cbuf);
		async_chan_send(s->done_ch, job);
	}
}


/* ftw callback for the streaming walk: stamp jobs with the walking
 * generation; abort instantly when a restart supersedes us. */
typedef struct gs_walk_ty {
	grep_stream_ty *s;
	unsigned long gen;
} gs_walk_ty;

JSTR_IO_FTW_FUNC(gs_traverse, ftw, args)
{
	gs_walk_ty *const w = (gs_walk_ty *)(void *)args;
	grep_stream_ty *const s = w->s;
	if (jstr_unlikely(s->stop))
		return JSTR_RET_ERR;
	async_lock_lock(s->cfg_mu);
	const int stale = (s->gen != w->gen);
	async_lock_unlock(s->cfg_mu);
	if (stale)
		return JSTR_RET_ERR;

	sjob_ty *const job = (sjob_ty *)calloc(1, sizeof(*job));
	if (jstr_unlikely(job == NULL))
		return JSTR_RET_SUCC;
	job->seq = 0;
	job->gen = w->gen;
	memcpy(job->path, ftw->dirpath, (size_t)ftw->dirpath_len);
	job->path[(size_t)ftw->dirpath_len] = '\0';
	job->path_len = (size_t)ftw->dirpath_len;
	job->st = *ftw->st;

	async_lock_lock(s->out_mu);
	job->seq = s->files_enqueued++;
	async_lock_unlock(s->out_mu);
	async_chan_send(s->work_ch, job);
	return JSTR_RET_SUCC;
}

/* Traversal thread: walks every queued dir for the current generation,
 * then publishes an end-of-generation control job. Restart-aware. */
static void *
gs_producer(void *R arg)
{
	grep_stream_ty *const s = (grep_stream_ty *)(void *)arg;
	unsigned long walked_gen = 0;
	size_t next_dir = 0;
	for (;;) {
		async_event_wait(s->restart);
		if (s->stop)
			break;
		async_event_clear(s->restart);
		async_lock_lock(s->cfg_mu);
		walked_gen = s->gen;
		async_lock_unlock(s->cfg_mu);

		for (;;) {
			async_lock_lock(s->cfg_mu);
			const int stale = (s->gen != walked_gen);
			const char *dir = NULL;
			if (!stale && next_dir < s->ndirs)
				dir = s->dirs[next_dir];
			async_lock_unlock(s->cfg_mu);
			if (stale)
				break;
			if (dir == NULL)
				break;
			++next_dir;
			gs_walk_ty w = { s, walked_gen };
			if (jstr_unlikely(jstr_chk(jstr_io_ftw(dir, gs_traverse, &w,
			    JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG, NULL, NULL)))) {
				/* Read error mid-walk: report the generation complete. */
				break;
			}
		}
		sjob_ty *const ctrl = (sjob_ty *)calloc(1, sizeof(*ctrl));
		if (ctrl != NULL) {
			ctrl->skip = 2;
			ctrl->gen = walked_gen;
			async_chan_send(s->done_ch, ctrl);
		}
		next_dir = 0;
	}
	return NULL;
}

static void
gs_publish(grep_stream_ty *R s, sjob_ty *R job)
{
	async_lock_lock(s->out_mu);
	if (job->nrecs > 0) {
		if (job->nrecs > s->staged_cap - s->staged_n) {
			const size_t ncap = (s->staged_cap + job->nrecs) * 2;
			grep_line_ty *const ns = (grep_line_ty *)realloc(s->staged, ncap * sizeof(*ns));
			if (ns != NULL) {
				s->staged = ns;
				s->staged_cap = ncap;
			}
		}
		const size_t room = s->staged_cap - s->staged_n;
		const size_t take = (job->nrecs < room) ? job->nrecs : room;
		if (take > 0) {
			memcpy(s->staged + s->staged_n, job->recs, take * sizeof(*job->recs));
			s->staged_n += take;
		}
		s->matches_total += job->nrecs + job->overflow;
	} else {
		s->matches_total += job->overflow;
	}
	s->files_done++;
	if (job->name != NULL && job->nrecs > 0) {
		if (s->sn == s->scap) {
			const size_t nc = s->scap ? s->scap * 2 : 16;
			char **const nn = (char **)realloc(s->staged_names, nc * sizeof(*nn));
			if (nn != NULL) {
				s->staged_names = nn;
				s->scap = nc;
				s->staged_names[s->sn++] = job->name;
				job->name = NULL;
			}
		} else {
			s->staged_names[s->sn++] = job->name;
			job->name = NULL;
		}
	}
	async_lock_unlock(s->out_mu);
}

/* Ordering thread: restores traversal order per generation and publishes
 * finished files to the staging area the UI polls. */
static void *
gs_orderer(void *R arg)
{
	grep_stream_ty *const s = (grep_stream_ty *)(void *)arg;
	sjob_ty **hold = NULL;
	size_t hold_n = 0, hold_cap = 0;
	unsigned long expected = 0;
	unsigned long long gen_enqueued = 0;
	unsigned long cur_gen = 0;
	int gen_valid = 0;
	int seen_control = 0;

	for (;;) {
		sjob_ty *job = (sjob_ty *)async_chan_recv(s->done_ch);
		if (job == NULL)
			break;

		/* Generation switch: drop everything from an older walk. */
		if (!gen_valid || job->gen != cur_gen) {
			for (size_t k = 0; k < hold_n; ++k)
				gs_job_free(hold[k]);
			hold_n = 0;
			expected = 0;
			gen_enqueued = 0;
			seen_control = 0;
			cur_gen = job->gen;
			gen_valid = 1;
		}

		if (job->skip == 2) {
			async_lock_lock(s->out_mu);
			gen_enqueued = s->files_enqueued;
			async_lock_unlock(s->out_mu);
			seen_control = 1;
			gs_job_free(job);
		} else if (job->seq == expected) {
publish_one:
			gs_publish(s, job);
			gs_job_free(job);
			++expected;
			size_t k = 0;
			while (k < hold_n) {
				if (hold[k]->seq == expected) {
					sjob_ty *const h = hold[k];
					memmove(hold + k, hold + k + 1, (hold_n - k - 1) * sizeof(*hold));
					--hold_n;
					job = h;
					goto publish_one;
				}
				++k;
			}
		} else {
			if (hold_n == hold_cap) {
				hold_cap = hold_cap ? hold_cap * 2 : 64;
				sjob_ty **const nh = (sjob_ty **)realloc(hold, hold_cap * sizeof(*nh));
				if (nh == NULL) {
					gs_job_free(job);
					continue;
				}
				hold = nh;
			}
			hold[hold_n++] = job;
			continue;
		}

		if (seen_control && expected >= gen_enqueued && hold_n == 0) {
			async_lock_lock(s->out_mu);
			s->done = 1;
			async_lock_unlock(s->out_mu);
		}
	}
	free(hold);
	return NULL;
}

/* Build an immutable version for GEN from the given scope. Returns NULL on
 * allocation/compile failure (the caller keeps the previous version). */
static gs_version_ty *
gs_version_build(unsigned long gen, const char *R find, size_t find_len,
                 const char *R fsub, size_t fsub_n,
                 const char *R inc, size_t inc_n,
                 const char *R exc, size_t exc_n,
                 int want_regex, int cflags, int eflags)
{
	gs_version_ty *v = (gs_version_ty *)calloc(1, sizeof(*v));
	if (jstr_unlikely(v == NULL))
		return NULL;
	v->gen = gen;
	v->want_regex = want_regex;
	v->eflags = eflags;
	if (find_len > 0) {
		v->find = (char *)malloc(find_len);
		if (jstr_unlikely(v->find == NULL)) {
			free(v);
			return NULL;
		}
		memcpy(v->find, find, find_len);
		v->find_len = find_len;
	}
	if (fsub_n > 0 && fsub != NULL) {
		v->fsub = (char *)malloc(fsub_n);
		if (v->fsub != NULL) {
			memcpy(v->fsub, fsub, fsub_n);
			v->fsub_n = fsub_n;
		}
	}
	int ok = 1;
	if (!want_regex && v->find_len > 0)
		jstr_memmem_comp(&v->tw, v->find, v->find_len);
	if (want_regex && v->find_len > 0) {
		const int rc = jstr_re_comp(&v->re, v->find, cflags);
		if (rc != JSTR_RE_RET_NOERROR)
			ok = 0;
	}
	if (inc_n > 0 && inc != NULL) {
		if (jstr_re_comp(&v->inc, inc, cflags) == JSTR_RE_RET_NOERROR)
			v->have_inc = 1;
	}
	if (exc_n > 0 && exc != NULL) {
		if (jstr_re_comp(&v->exc, exc, cflags) == JSTR_RE_RET_NOERROR)
			v->have_exc = 1;
	}
	if (jstr_unlikely(!ok)) {
		/* Bad find regex: version matches nothing (workers still walk and
		 * count files, so progress stays truthful); UI surfaces the error. */
		v->find_len = 0;
		if (v->find != NULL) {
			free(v->find);
			v->find = NULL;
		}
	}
	return v;
}

grep_stream_ty *
grep_stream_start(const char *R dir, size_t nwork,
                  const char *R find, size_t find_len)
{
	grep_stream_ty *s = (grep_stream_ty *)calloc(1, sizeof(*s));
	if (jstr_unlikely(s == NULL))
		return NULL;
	nwork = gs_nwork(nwork);
	s->cfg_mu = async_lock_new();
	s->out_mu = async_lock_new();
	s->restart = async_event_new();
	s->work_ch = async_chan_new(PIPELINE_DEPTH);
	s->done_ch = async_chan_new(PIPELINE_DEPTH * 2);
	s->buf_ch = async_chan_new(PIPELINE_DEPTH * 2);
	if (jstr_unlikely(s->cfg_mu == NULL || s->out_mu == NULL || s->restart == NULL ||
	                  s->work_ch == NULL || s->done_ch == NULL || s->buf_ch == NULL))
		goto fail;

	s->ndirs = 1;
	s->dirs = (const char **)malloc(4 * sizeof(*s->dirs));
	if (jstr_unlikely(s->dirs == NULL))
		goto fail;
	s->dirs[0] = dir;

	async_lock_lock(s->cfg_mu);
	s->gen = 1;
	s->versions = gs_version_build(1, find, find_len, NULL, 0, NULL, 0, NULL, 0,
	                               (G.mode & MODE_USE_REGEX), G.cflags, G.eflags);
	async_lock_unlock(s->cfg_mu);
	if (jstr_unlikely(s->versions == NULL))
		goto fail;

	for (size_t k = 0; k < nwork * 2; ++k) {
		jstr_ty *b = (jstr_ty *)malloc(sizeof(*b));
		DIE_IF(b == NULL, "%s", "Out of memory.\n");
		*b = (jstr_ty)JSTR_INIT;
		async_chan_send(s->buf_ch, b);
	}

	s->orderer = async_thread_run(gs_orderer, s);
	DIE_IF(s->orderer == NULL, "%s", "Can't start the ordering thread.\n");
	for (size_t k = 0; k < nwork; ++k)
		async_pool_submit(gs_worker_task, s);
	s->producer = async_thread_run(gs_producer, s);
	DIE_IF(s->producer == NULL, "%s", "Can't start the traversal thread.\n");
	async_event_set(s->restart); /* kick the initial walk */
	return s;
fail:
	grep_stream_stop(s);
	return NULL;
}

void
grep_stream_add_dir(grep_stream_ty *R s, const char *R dir)
{
	if (jstr_unlikely(s == NULL || dir == NULL))
		return;
	async_lock_lock(s->cfg_mu);
	const char **const nd = (const char **)realloc(s->dirs, (s->ndirs + 1) * sizeof(*nd));
	if (nd != NULL) {
		s->dirs = nd;
		s->dirs[s->ndirs++] = dir;
	}
	async_lock_unlock(s->cfg_mu);
}

void
grep_stream_configure(grep_stream_ty *R s, const char *R find, size_t find_len,
                      const char *R fsub, size_t fsub_n,
                      const char *R inc, size_t inc_n,
                      const char *R exc, size_t exc_n,
                      int want_regex, int cflags, int eflags)
{
	if (jstr_unlikely(s == NULL))
		return;
	async_lock_lock(s->cfg_mu);
	const unsigned long gen = ++s->gen;
	gs_version_ty *const v = gs_version_build(gen, find, find_len, fsub, fsub_n,
	                                          inc, inc_n, exc, exc_n,
	                                          want_regex, cflags, eflags);
	if (v != NULL) {
		v->next = s->versions;
		s->versions = v;
	}
	async_lock_unlock(s->cfg_mu);
	/* Reset per-generation progress; drop unadopted staging. */
	async_lock_lock(s->out_mu);
	s->files_enqueued = 0;
	s->files_done = 0;
	s->done = 0;
	async_lock_unlock(s->out_mu);
	async_event_set(s->restart);
}

size_t
grep_stream_poll(grep_stream_ty *R s, grep_batch_ty *R batch, int *done)
{
	size_t n = 0;
	batch->lines = NULL;
	batch->n = 0;
	batch->names = NULL;
	batch->names_n = 0;
	batch->arenas = NULL;
	batch->arenas_n = 0;
	if (jstr_unlikely(s == NULL)) {
		*done = 1;
		return 0;
	}
	async_lock_lock(s->out_mu);
	if (s->staged_n > 0) {
		batch->lines = s->staged;
		batch->n = s->staged_n;
		batch->names = s->staged_names;
		batch->names_n = s->sn;
		batch->arenas = NULL;
		batch->arenas_n = 0;
		n = s->staged_n;
		s->staged = NULL;
		s->staged_n = 0;
		s->staged_cap = 0;
		s->staged_names = NULL;
		s->sn = 0;
		s->scap = 0;
	}
	if (done != NULL)
		*done = s->done;
	async_lock_unlock(s->out_mu);
	return n;
}

unsigned long
grep_stream_files_done(grep_stream_ty *R s)
{
	if (s == NULL)
		return 0;
	async_lock_lock(s->out_mu);
	const unsigned long n = s->files_done;
	async_lock_unlock(s->out_mu);
	return n;
}

unsigned long
grep_stream_files_total(grep_stream_ty *R s)
{
	if (s == NULL)
		return 0;
	async_lock_lock(s->out_mu);
	const unsigned long n = s->files_enqueued;
	async_lock_unlock(s->out_mu);
	return n;
}

int
grep_stream_is_done(grep_stream_ty *R s)
{
	if (s == NULL)
		return 1;
	async_lock_lock(s->out_mu);
	const int d = s->done;
	async_lock_unlock(s->out_mu);
	return d;
}

unsigned long long
grep_stream_matches(grep_stream_ty *R s)
{
	if (s == NULL)
		return 0;
	async_lock_lock(s->out_mu);
	const unsigned long long n = s->matches_total;
	async_lock_unlock(s->out_mu);
	return n;
}

void
grep_stream_stop(grep_stream_ty *R s)
{
	if (s == NULL)
		return;
	s->stop = 1;
	async_event_set(s->restart);
	async_chan_close(s->work_ch);
	async_chan_close(s->done_ch);
	async_chan_close(s->buf_ch);
	async_thread_join(s->producer);
	if (s->orderer != NULL)
		async_thread_join(s->orderer);
	async_pool_barrier();
	async_chan_free(s->work_ch);
	async_chan_free(s->done_ch);
	async_chan_free(s->buf_ch);
	gs_version_ty *v = s->versions;
	while (v != NULL) {
		gs_version_ty *const nx = v->next;
		free(v->find);
		free(v->fsub);
		if (v->have_inc)
			jstr_re_free(&v->inc);
		if (v->have_exc)
			jstr_re_free(&v->exc);
		if (v->want_regex && v->find_len > 0)
			jstr_re_free(&v->re);
		free(v);
		v = nx;
	}
	async_lock_lock(s->out_mu);
	grep_line_ty *const sl = s->staged;
	char **const sn = s->staged_names;
	const size_t snn = s->sn;
	async_lock_unlock(s->out_mu);
	for (size_t k = 0; k < snn; ++k)
		free(sn[k]);
	free(sn);
	free(sl);
	async_lock_free(s->cfg_mu);
	async_lock_free(s->out_mu);
	async_event_free(s->restart);
	free(s->dirs);
	free(s);
}
