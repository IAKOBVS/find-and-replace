/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef IO_H
#define IO_H

#include "common.h"

/**
 * @brief Wrap stat(2) and normalize its result.
 * @details Calls stat(2) once and converts a failure to `JSTR_RET_ERR`.
 *          The caller owns FILE and BUF; no ownership is transferred.
 * @pre FILE is a valid readable path string; BUF points to writable storage.
 * @param file NUL-terminated path to stat.
 * @param buf Destination for the struct stat result.
 * @return `JSTR_RET_SUCC` on success; `JSTR_RET_ERR` when stat(2) fails.
 * @post On success BUF contains the stat result; on failure BUF is unspecified.
 * @par Side Effects:
 *   One stat(2) syscall; no global state is modified.
 * @par Threading and Reentrancy:
 *   Any thread; no shared mutable state.
 */
jstr_ret_ty xstat(const char *R file, struct stat *R buf);

/**
 * @brief Test whether a path exists.
 * @details Uses access(F_OK) so read-only and write-only files still count as existing.
 * @pre FNAME is a valid NUL-terminated path string.
 * @param fname Path to test.
 * @return Nonzero when the path exists; zero otherwise.
 * @post No state is modified.
 * @par Side Effects:
 *   One access(2) syscall.
 * @par Threading and Reentrancy:
 *   Any thread; no shared mutable state.
 */
int file_exists(const char *R fname);

/**
 * @brief Replace a file in place while preserving a backup.
 * @details Renames FNAME to FNAME+G.bak_suffix, writes BUF to FNAME with the
 *          original permission bits, and reports rename/write failures.
 * @pre The backup target must not exist; G.bak_suffix is set and non-NULL.
 * @param buf Complete replacement content.
 * @param fname Original file path.
 * @param fname_len Byte length of FNAME.
 * @param st Original file status used to restore permissions.
 * @return `JSTR_RET_SUCC` on success; `JSTR_RET_ERR` on rename/write failure.
 * @post On success FNAME contains BUF and the backup contains the original file.
 * @par Side Effects:
 *   Renames FNAME, writes FNAME, may call jstr_errdie on invalid input.
 * @par Threading and Reentrancy:
 *   Stage B worker.
 */
jstr_ret_ty io_write_inplace_backup(const jstr_ty *R buf, const char *R fname,
                                    size_t fname_len, const struct stat *st);

/**
 * @brief Replace a file in place through a temporary file.
 * @details Writes BUF to a uniquely named temporary file in the same directory
 *          and renames it over FNAME. Fatal failures terminate the process.
 * @pre FNAME is a valid path; BUF contains the full replacement content.
 * @param buf Complete replacement content.
 * @param fname Destination path.
 * @param fname_len Byte length of FNAME.
 * @post On success FNAME contains BUF and the temp file no longer exists.
 * @par Side Effects:
 *   Creates, writes, and renames a temporary file; may exit on failure.
 * @par Threading and Reentrancy:
 *   Stage B worker.
 */
void io_write_inplace_temp(const jstr_ty *R buf, const char *R fname,
                           size_t fname_len);

#endif /* IO_H */
