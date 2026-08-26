/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef PIPELINE_H
#define PIPELINE_H

#include "common.h"
#include "files.h"

/* Threaded recursive pipeline: a dedicated traversal thread walks DIR with
 * ftw and enqueues every regular file into a bounded ring; NWORK worker
 * threads read/replace/write the files with private buffers; the CALLING
 * thread acts as the emitter and releases all output strictly in traversal
 * order, so stdout/stderr bytes match a sequential run exactly.
 *
 * Per-file failures without a message are counted into A->err_count (same
 * accumulation contract as the sequential walk). A fatal job error (backup
 * collision, temp-file failure, ...) is printed by the emitter and reported
 * through *FATAL_OUT; the caller then exits with err_exit_code().
 *
 * Returns JSTR_RET_SUCC when the traversal itself completed; any other value
 * mirrors an ftw-level failure for the caller to report. */
jstr_ret_ty pipeline_run_dir(const char *R dir, args_ty *R a, size_t nwork, int *fatal_out);

/* Same pipeline in COLLECT mode for the interactive TUIs: the traversal
 * thread + reader threads load every file; the calling (UI) thread caches
 * them into G.files via file_pushback, strictly in traversal order, so the
 * tty editors open on a fully ordered cache. Binary files are skipped;
 * unreadable files are counted into A->err_count like the sequential walk. */
jstr_ret_ty pipeline_collect_dir(const char *R dir, args_ty *a, size_t nwork);

/* ---------------------------------------------------------------------------
 * STREAMING GREP (tty --grep, fixed-string): the TUI opens IMMEDIATELY while
 * traversal + pool readers scan files AT LOAD TIME -- nothing is cached; only
 * match records (with copied line bytes, width-capped) survive. The UI polls
 * for traversal-ordered batches and renders progress live. Editing the find/
 * filters restarts the walk (files are simply re-read from disk).
 * ------------------------------------------------------------------------- */
typedef struct grep_stream_ty grep_stream_ty;

grep_stream_ty *grep_stream_start(const char *R dir, size_t nwork,
                                  const char *R find, size_t find_len);
/* Walk another directory after the current queue drains (argv-stable ptr). */
void grep_stream_add_dir(grep_stream_ty *R s, const char *R dir);
/* Replace pattern + filters; restarts the walk from scratch (bumps the
 * generation; in-flight stale work is discarded without I/O). Buffer args
 * may be NULL/0 when inactive; WANT_REGEX selects the regex matcher. */
void grep_stream_configure(grep_stream_ty *R s, const char *R find, size_t find_len,
                           const char *R fsub, size_t fsub_n,
                           const char *R inc, size_t inc_n,
                           const char *R exc, size_t exc_n,
                           int want_regex, int cflags, int eflags);

/* Newly finished files in traversal order, valid until the next POLL. The
 * UI adopts records into its own lists and takes ownership of NAMES and
 * ARENAS storage (free() each element when discarding results). */
typedef struct grep_batch_ty {
	grep_line_ty *lines;
	size_t n;
	char **names;
	size_t names_n;
	char **arenas;
	size_t arenas_n;
} grep_batch_ty;

/* Adopt everything finished since last poll; *DONE set when the whole scope
 * has been walked for the current generation. Returns batch record count. */
size_t grep_stream_poll(grep_stream_ty *R s, grep_batch_ty *R batch, int *done);
unsigned long grep_stream_files_done(grep_stream_ty *R s);
unsigned long grep_stream_files_total(grep_stream_ty *R s);
int grep_stream_is_done(grep_stream_ty *R s);
/* Total matching lines seen, including records dropped by retention caps. */
unsigned long long grep_stream_matches(grep_stream_ty *R s);
void grep_stream_stop(grep_stream_ty *R s);

#endif /* PIPELINE_H */
