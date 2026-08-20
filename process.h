/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef PROCESS_H
#define PROCESS_H

#include "common.h"

/* Buffer and per-file replacement. */
jstr_ret_ty process_buffer(const jstr_twoway_ty *R t, jstr_ty *R buf,
                           const char *R fname, size_t fname_len,
                           const struct stat *st, const char *R find,
                           const size_t find_len, const char *R rplc,
                           const size_t rplc_len);
jstr_ret_ty process_file(const jstr_twoway_ty *R t, jstr_ty *R buf,
                         const char *R fname, size_t fname_len,
                         const struct stat *st, const char *R find,
                         const size_t find_len, const char *R rplc,
                         const size_t rplc_len);

/* --grep mode: print every line of BUF matching FIND (fixed or regex) to
 * stdout. FNAME != NULL prefixes each printed line with "FNAME:" (stdin has
 * no prefix). Sets G.grep_matched so main can return grep's exit code. */
jstr_ret_ty grep_scan_file(const jstr_twoway_ty *R t, const jstr_ty *R buf,
                           const char *R fname, size_t fname_len,
                           const char *R find, size_t find_len);

/* --grep TUI: collect every matching line into G.grep_lines instead of
 * printing. FNAME/FNAME_LEN identify the source file. */
void grep_collect_file(const jstr_twoway_ty *R t, const jstr_ty *R buf,
                       const char *R fname, size_t fname_len,
                       const char *R find, size_t find_len,
                       unsigned int file_idx);

#endif /* PROCESS_H */
