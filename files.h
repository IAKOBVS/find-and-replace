/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef FILES_H
#define FILES_H

#include "common.h"

/* Max size of total file content to keep in memory.  */
#define FILE_CACHE_MAX (16 * JSTR_IO_GIB)
#define FILES_CAP_MIN  8

/* Per-directory-traversal context passed through ftw to callback_file. */
typedef struct args_ty {
	jstr_ty *buf;
	jstr_literal_ty find;
	jstr_literal_ty rplc;
	const jstr_twoway_ty *t;
} args_ty;

/* stat() wrapper and backup-name existence check. */
JSTR_FUNC jstr_ret_ty xstat(const char *R file, struct stat *R buf);
int file_exists(const char *R fname);

/* ftw traversal callback and --include/--exclude matcher (reads the compiled
 * regexes in the global state; the args pointer is ignored). */
JSTR_IO_FTW_FUNC(callback_file, ftw, args);
JSTR_IO_FTW_FUNC_MATCH(matcher, fname, fname_len, args);

/* Append one file to the -c confirm cache. */
void file_pushback(files_ty *files, const jstr_literal_ty *fname,
                   const struct stat *st, jstr_ty *R buf);

#endif /* FILES_H */
