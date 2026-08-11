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

#endif /* PROCESS_H */
