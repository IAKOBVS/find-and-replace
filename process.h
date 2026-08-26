/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef PROCESS_H
#define PROCESS_H

#include "common.h"

/* Pipeline job result flags (written by pipeline_process_file, read by the
 * pipeline emitter on the main thread). */
#define PIPELINE_F_CHANGED 1 /* an in-place edit was performed */
#define PIPELINE_F_MATCHED 2 /* --grep found at least one matching line */

/* Buffer and per-file replacement. PE != NULL captures fatal errors for the
 * caller (pipeline workers) instead of printing and exiting. */
jstr_ret_ty process_buffer(const jstr_twoway_ty *R t, jstr_ty *R buf,
                           const char *R fname, size_t fname_len,
                           const struct stat *st, const char *R find,
                           const size_t find_len, const char *R rplc,
                           const size_t rplc_len, proc_err_ty *R pe);
jstr_ret_ty process_file(const jstr_twoway_ty *R t, jstr_ty *R buf,
                         const char *R fname, size_t fname_len,
                         const struct stat *st, const char *R find,
                         const size_t find_len, const char *R rplc,
                         const size_t rplc_len);

/* Worker-side per-file processing for the threaded recursive pipeline: reads
 * FNAME into BUF (worker-private), runs the replacement engine or the grep
 * scan, performs in-place writes itself, and stores everything the emitter
 * must print (replaced content for stdout mode, formatted matching lines for
 * --grep) into OUT. Never touches stdio streams and never exits: fatal errors
 * are rendered into PE and reported through the JSTR_RET_ERR return. FLAGS_OUT
 * receives PIPELINE_F_CHANGED / PIPELINE_F_MATCHED. */
jstr_ret_ty pipeline_process_file(const jstr_twoway_ty *R t, jstr_ty *R buf,
                                  const char *R fname, size_t fname_len,
                                  const struct stat *st, const char *R find,
                                  size_t find_len, const char *R rplc,
                                  size_t rplc_len, proc_err_ty *R pe,
                                  jstr_ty *R out, int *flags_out);

/* Echo a changed file path to stderr (unless quiet) and to stdout with -l.
 * Runs only on the emitter (main) thread so output stays ordered. */
jstr_ret_ty report_changed_file(const char *R fname, size_t fname_len);

/* Pipeline collect-mode read (tty TUI caches): load FNAME wholly into BUF
 * and sniff for NUL bytes. Returns one of: */
#define PIPELINE_READ_OK     0
#define PIPELINE_READ_BINARY 1
#define PIPELINE_READ_ERR    (-1)
int pipeline_read_file(jstr_ty *R buf, const char *R fname, size_t fname_len,
                       const struct stat *st);

/* --grep mode: print every line of BUF matching FIND (fixed or regex) to
 * stdout. FNAME != NULL prefixes each printed line with "FNAME:" (stdin has
 * no prefix). Sets G.grep_matched so main can return grep's exit code. */
jstr_ret_ty grep_scan_file(const jstr_twoway_ty *R t, const jstr_ty *R buf,
                           const char *R fname, size_t fname_len,
                           const char *R find, size_t find_len);

/* --grep TUI: collect every matching line into DST (or G.grep_lines via the
 * wrapper) instead of printing. Never touches G.grep_matched -- callers
 * track matches themselves so worker chunks stay independent. */
void grep_collect_file_into(grep_lines_ty *R dst, const jstr_twoway_ty *R t,
                            const jstr_ty *R buf, const char *R fname,
                            size_t fname_len, const char *R find,
                            size_t find_len);
void grep_collect_file(const jstr_twoway_ty *R t, const jstr_ty *R buf,
                       const char *R fname, size_t fname_len,
                       const char *R find, size_t find_len);

#endif /* PROCESS_H */
