/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef PROCESS_H
#define PROCESS_H

#include "common.h"
#include "stage.h"
#include "thread_compat.h"

/* Processor-stage variant: reads into *BUF, performs in-place writes, and
 * returns stdout/cache payloads in RES without touching stdio or G caches.
 * On transfer, RES->out takes ownership of *BUF and *BUF becomes NULL. */
jstr_ret_ty process_job(const jstr_twoway_ty *R t, jstr_ty **R buf,
                        const char *R fname, size_t fname_len,
                        const struct stat *st, const char *R find,
                        const size_t find_len, const char *R rplc,
                        const size_t rplc_len, process_result_ty *R res);

jstr_ret_ty far_compile(jstr_twoway_ty *R t, const char *R find, size_t find_len, const char *R rplc, size_t rplc_len, int force_recompile, char *err_buf, size_t err_size);
far_thread_ret_ty process_thread(void *arg);

/* --grep TUI: collect every matching line into G.grep_lines instead of
 * printing. FNAME/FNAME_LEN identify the source file. */
void grep_collect_file(const jstr_twoway_ty *R t, const jstr_ty *R buf,
                       const char *R fname, size_t fname_len,
                       const char *R find, size_t find_len);
void grep_collect_file_n(const jstr_twoway_ty *R t, const jstr_ty *R buf,
                         const char *R fname, size_t fname_len,
                         const char *R find, size_t find_len, size_t limit);

#endif /* PROCESS_H */
