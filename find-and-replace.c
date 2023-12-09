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

typedef enum {
	PRINT_STDOUT = 0,
	PRINT_FILE,
	PRINT_FILE_BACKUP,
} print_mode_ty;

typedef struct global_ty {
	const char *file_pattern;
	int print_mode;
	int recursive;
} global_ty;
global_ty G = { 0 };

JSTR_FUNC
JSTR_ATTR_INLINE
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

static void
backup_make(char *R dst, const char *R src)
{
	jstr_strcpy_len(jstr_mempcpy(dst, src, jstr_strnlen(src, JSTRIO_NAME_MAX)), ".bak", sizeof(".bak") - 1);
}

static int
file_exists(const char *R fname)
{
	return access(fname, F_OK | W_OK | R_OK) == 0;
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
	jstrio_ft_ty ft = jstrio_exttype(buf->data, buf->size);
	if (ft == JSTRIO_FT_BINARY)
		return JSTR_RET_SUCC;
	if (jstr_chk(jstrio_freadfile_len_j(buf, fname, "r", file_size)))
		goto err;
	if (ft == JSTRIO_FT_UNKNOWN)
		if (jstr_isbinary(buf->data, 64, buf->size))
			return JSTR_RET_SUCC;
	const size_t changed = jstr_rplcall_len_j(buf, find, find_len, rplc, rplc_len);
	if (changed == (size_t)-1)
		goto err;
	if (changed == 0)
		return JSTR_RET_SUCC;
	if (G.print_mode == PRINT_STDOUT) {
		jstrio_fwrite(buf->data, 1, buf->size, stdout);
		if (buf->size && *(buf->data + buf->size - 1) != '\n')
			jstrio_putchar('\n');
	} else {
		char bak[JSTRIO_NAME_MAX + 4 + 1];
		backup_make(bak, fname);
		if (jstr_unlikely(file_exists(bak)))
			goto err;
		if (G.print_mode == PRINT_FILE_BACKUP)
			if (jstr_unlikely(rename(fname, bak)))
				goto err;
		if (jstr_chk(jstrio_fwritefile_len_j(buf, fname, "w")))
			goto err;
	}
	return JSTR_RET_SUCC;
err:
	DIE();
	JSTR_RETURN_ERR(JSTR_RET_ERR);
}

typedef struct args_ty {
	jstr_ty *buf;
	const char *find;
	size_t find_len;
	const char *rplc;
	size_t rplc_len;
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

int
main(int argc, char **argv)
{
	if (jstr_nullchk(argv[1]) || jstr_nullchk(argv[2]) || jstr_nullchk(argv[3])) {
		PRINTERR("Usage: %s [FIND] [REPLACE] [OPTIONS]... [FILES]...\n"
		         "Options:\n"
		         "  -i, -i.bak\n"
		         "    Instead of printing to stdout, replace the files in-place.\n"
		         "    If .bak is provided, backup the original file prefixed with .bak.\n"
		         "  -r\n"
		         "    Recurse on the arguments given if they are directories.\n"
		         "  -name pattern\n"
		         "    File to match when -r is used. Pattern is a wildcard.\n"
		         "    If -name is used without -r, behavior is undefined.\n"
		         "\n"
		         "FIND and REPLACE shall be placed in that exact order.\n",
		         argv[0]);
		return EXIT_FAILURE;
	}
	jstr_ty buf = JSTR_INIT;
	DIE_IF(jstr_chk(jstr_reserve_j(&buf, 4096)));
	struct stat st;
	const size_t find_len = strlen(FIND);
	const size_t rplc_len = strlen(RPLC);
	for (unsigned int i = 3; ARG; ++i) {
		if (G.print_mode == 0) {
			if (!jstr_strcmpeq_loop(ARG, "-i.bak")) {
				G.print_mode = PRINT_FILE_BACKUP;
				continue;
			} else if (!jstr_strcmpeq_loop(ARG, "-i")) {
				G.print_mode = PRINT_FILE;
				continue;
			}
		}
		if (G.recursive == 0) {
			if (!jstr_strcmpeq_loop(ARG, "-r")) {
				G.recursive = 1;
				continue;
			}
		}
		if (G.file_pattern == NULL) {
			if (!jstr_strcmpeq_loop(ARG, "-name")) {
				++i;
				if (jstr_nullchk(ARG))
					jstr_errdie("No argument after -name flag.");
				G.file_pattern = ARG;
				continue;
			}
		}
		int ret = STAT(ARG, &st);
		DIE_IF(ret == JSTR_RET_ERR);
		if (ret != JSTR_RET_SUCC)
			continue;
		if (IS_REG(st.st_mode)) {
			DIE_IF(jstr_chk(process_file(&buf, ARG, (size_t)st.st_size, FIND, find_len, RPLC, rplc_len)));
		} else if (IS_DIR(st.st_mode)) {
			if (G.recursive) {
				args_ty a = { &buf, FIND, find_len, RPLC, rplc_len };
				DIE_IF(!jstr_chk(jstrio_ftw(ARG, callback_file, &a, JSTRIO_FTW_REG | JSTRIO_FTW_STATREG, G.file_pattern, 0)));
			}
		} else {
			PRINTERR("stat() failed on %s.\n", ARG);
			exit(EXIT_FAILURE);
		}
	}
	jstr_free_j(&buf);
	return EXIT_SUCCESS;
	(void)argc;
}
