/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "io.h"

/**
 * @brief Wrap stat(2) and normalize its result.
 *
 * @details This function is part of the io.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param file parameter defined by the owning module contract.
 * @param buf growable byte buffer.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B or main; filesystem operations are independent.
 */
JSTR_FUNC
jstr_ret_ty
xstat(const char *R file, struct stat *R buf)
{
	if (jstr_unlikely(stat(file, buf)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_SUCC;
}

/**
 * @brief Test whether a path exists.
 *
 * @details This function is part of the io.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param fname file name.
 * @return Nonzero when the condition holds; zero otherwise.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B or main; filesystem operations are independent.
 */
int
file_exists(const char *R fname)
{
	return access(fname, F_OK) == 0;
}

/**
 * @brief Replace a file in place while preserving a backup.
 *
 * @details This function is part of the io.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param buf growable byte buffer.
 * @param fname file name.
 * @param fname_len FNAME byte length.
 * @param st file status.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B or main; filesystem operations are independent.
 */
jstr_ret_ty
io_write_inplace_backup(const jstr_ty *R buf, const char *R fname, size_t fname_len, const struct stat *st)
{
	char bak[JSTR_IO_PATH_MAX];
	jstr_ret_ty ret = JSTR_RET_SUCC;
	if (jstr_unlikely(fname_len + G.bak_suffix_len >= sizeof(bak)))
		jstr_errdie("Suffix length is too large to create a backup file (%zu >= %zu).\n", fname_len + G.bak_suffix_len, sizeof(bak));
	char *p = jstr_mempcpy(bak, fname, fname_len);
	jstr_strcpy_len(p, G.bak_suffix, G.bak_suffix_len);
	if (jstr_unlikely(file_exists(bak)))
		jstr_errdie("Can't make a backup file because suffixed filename (%s) already exists.\n", bak);
	if (jstr_unlikely(rename(fname, bak))) {
		ret = JSTR_RET_ERR;
		goto out;
	}
	if (jstr_chk(jstr_io_writefile_len_j(buf, fname, O_CREAT | O_TRUNC | O_WRONLY, st->st_mode & (S_IRWXO | S_IRWXG | S_IRWXU)))) {
		ret = JSTR_RET_ERR;
		goto out;
	}
out:
	return ret;
}

/**
 * @brief Replace a file in place through a temporary file.
 *
 * @details This function is part of the io.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param buf growable byte buffer.
 * @param fname file name.
 * @param fname_len FNAME byte length.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Stage B or main; filesystem operations are independent.
 */
void
io_write_inplace_temp(const jstr_ty *R buf, const char *R fname, size_t fname_len)
{
	char bak[JSTR_IO_PATH_MAX];
	if (jstr_unlikely(fname_len + S_LEN(".XXXXXX") >= sizeof(bak)))
		jstr_errdie("Filename (%s) is too large to create a backup file (%zu >= %zu).\n", fname, fname_len + S_LEN(".XXXXXX"), sizeof(bak));
	char *p = jstr_mempcpy(bak, fname, fname_len);
	p = jstr_stpcpy_len(p, S_LITERAL(".XXXXXX"));
	const int fd_tmp = mkstemp(bak);
	if (jstr_unlikely(fd_tmp == -1))
		jstr_errdie("Can't make a file (%s) to temporarily write replacements to.\n", bak);
	if (jstr_chk(jstr_io_writefilefd_len_j(buf, fd_tmp)))
		jstr_errdie("Can't write replacements to temp file (%s).\n", bak);
	if (jstr_unlikely(close(fd_tmp) == -1))
		jstr_errdie("Can't close temp file (%s).\n", bak);
	if (jstr_unlikely(rename(bak, fname)))
		jstr_errdie("Can't rename temp file (%s) to original file (%s).\n", bak, fname);
}
