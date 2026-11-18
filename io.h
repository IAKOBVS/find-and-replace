/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef IO_H
#define IO_H

#include "common.h"

jstr_ret_ty xstat(const char *R file, struct stat *R buf);
int file_exists(const char *R fname);
jstr_ret_ty io_write_inplace_backup(const jstr_ty *R buf, const char *R fname,
                                    size_t fname_len, const struct stat *st);
void io_write_inplace_temp(const jstr_ty *R buf, const char *R fname,
                           size_t fname_len);

#endif /* IO_H */
