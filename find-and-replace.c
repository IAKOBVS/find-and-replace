/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023 James Tirta Halim <tirtajames45 at gmail dot com>
   This file is part of find-and-replace.

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.

   MIT License (Expat) */

#define JSTR_PANIC                1
#define JSTR_USE_UNLOCKED_IO_READ 1

#include "./jstring/jstr/jstr.h"
#include "./jstring/jstr/jstr-io.h"

#define PRINTERR(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)
#define DIE_IF_PRINT(x, msg)              \
	do {                              \
		if (jstr_unlikely(x))     \
			jstr_errdie(msg); \
	} while (0)
#define DIE_IF(x)   DIE_IF_PRINT(x, "")
#define DIE()       DIE_IF(1)
#define ARG         argv[i]
#define unlikely(x) jstr_unlikely(x)
#define IS_REG(x)   S_ISREG(x)
#define IS_DIR(x)   S_ISDIR(x)
#define FIND        argv[1]
#define RPLC        argv[2]
#define R           JSTR_RESTRICT

static jstr_ret_ty
STAT(const char *R file,
     struct stat *R buf)
{
	if (unlikely(stat(file, buf)))
		goto err;
	return JSTR_RET_SUCC;
err:
	if (errno == EINVAL) {
		DIE();
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	return JSTR_RET_ERR - 1;
}

static jstr_ret_ty
process_file(jstr_ty *R buf,
             const char *R fname,
             const size_t file_size,
             const char *R find,
             const size_t find_len,
             const char *R rplc,
             const size_t rplc_len)
{
	if (jstr_chk(jstrio_freadfile_len_j(buf, fname, file_size)))
		goto err;
	if (jstr_chk(jstr_rplcall_len_j(buf, find, find_len, rplc, rplc_len)))
		goto err;
	if (jstr_chk(jstrio_writefile_len_j(buf, fname, O_WRONLY)))
		goto err;
	return JSTR_RET_SUCC;
err:
	DIE();
	JSTR_RETURN_ERR(JSTR_RET_ERR);
}

#if 0

typedef struct args_ty {
	jstr_ty *buf;
	const char *find;
	const char *rplc;
	size_t rplc_len;
	size_t find_len;
} args_ty;

static JSTRIO_FTW_FUNC(callback_file, ftw, args)
{
	const args_ty *const a = args;
	if (jstr_chk(process_file(a->buf, ftw->dirpath, (size_t)ftw->st->st_size, a->find, a->find_len, a->rplc, a->rplc_len)))
		goto err;
	return JSTR_RET_SUCC;
err:
	JSTR_RETURN_ERR(JSTR_RET_ERR);
}

static jstr_ret_ty
process_dir(jstr_ty *R buf,
            const char *R dir,
            const char *R find,
            const size_t find_len,
            const char *R rplc,
            const size_t rplc_len)
{
	args_ty args;
	args.buf = buf;
	args.find = find;
	args.find_len = find_len;
	args.rplc = rplc;
	args.rplc_len = rplc_len;
	if (jstr_chk(jstrio_ftw(dir, callback_file, &args, JSTRIO_FTW_STATREG | JSTRIO_FTW_REG | JSTRIO_FTW_DIR, NULL, 0)))
		goto err;
	return JSTR_RET_SUCC;
err:
	JSTR_RETURN_ERR(JSTR_RET_ERR);
}

#endif

int
main(int argc, char **argv)
{
	if (jstr_nullchk(argv[1]) || jstr_nullchk(argv[2]) || jstr_nullchk(argv[3])) {
		PRINTERR("Usage: %s <find> <replace> <file> <other files> ...\n", argv[0]);
		return EXIT_FAILURE;
	}
	jstr_ty buf = JSTR_INIT;
	DIE_IF(jstr_reserve_j(&buf, 4096) == JSTR_RET_ERR);
	struct stat st;
	const size_t find_len = strlen(FIND);
	const size_t rplc_len = strlen(RPLC);
	for (unsigned int i = 1; argv[i]; ++i) {
		int ret = STAT(ARG, &st);
		DIE_IF(ret == JSTR_RET_ERR);
		if (ret != JSTR_RET_SUCC)
			continue;
		if (IS_REG(st.st_mode))
			DIE_IF(jstr_chk(process_file(&buf, ARG, (size_t)st.st_size, FIND, find_len, RPLC, rplc_len)));
		else
			PRINTERR("stat() failed on %s.\n", ARG);
	}
	jstr_free_j(&buf);
	return EXIT_SUCCESS;
	(void)argc;
}
