/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef PROCESS_H
#define PROCESS_H

#include "common.h"

/* Buffer and per-file replacement. */
jstr_ret_ty process_buffer(const jstr_twoway_ty *R t, jstr_ty *R buf,
                           const jstr_literal_ty *fname,
                           const struct stat *st,
                           const jstr_literal_ty *find,
                           const jstr_literal_ty *rplc);
jstr_ret_ty process_file(const jstr_twoway_ty *R t, jstr_ty *R buf,
                         const jstr_literal_ty *fname,
                         const struct stat *st,
                         const jstr_literal_ty *find,
                         const jstr_literal_ty *rplc);

#endif /* PROCESS_H */
