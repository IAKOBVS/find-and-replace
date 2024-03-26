/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023 James Tirta Halim <tirtajames45 at gmail dot com>
 * This file is part of find-and-replace.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * MIT License (Expat) */

#define JSTR_PANIC                1
#define JSTR_USE_UNLOCKED_IO_READ 1
#define REGEX_IS_IMPLEMENTED      0

#include <jstr/jstr.h>
#include <jstr/jstr-io.h>
#if REGEX_IS_IMPLEMENTED
#	include <jstr/jstr-regex.h>
#endif
#include <fnmatch.h>

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

#define DO_FREE 0

typedef enum {
	PRINT_STDOUT = 0,
	PRINT_FILE,
	PRINT_FILE_BACKUP,
} print_mode_ty;

typedef struct global_ty {
	const char *file_pattern;
	int print_mode;
	int recursive;
	int compiled;
#if REGEX_IS_IMPLEMENTED
	regex_t regex;
	int regex_use;
	int cflags;
#endif
} global_ty;
global_ty G = { 0 };

JSTR_FUNC
JSTR_ATTR_INLINE
static jstr_ret_ty
xstat(const char *R file,
      struct stat *R buf)
{
	if (unlikely(stat(file, buf)))
		goto err;
	return JSTR_RET_SUCC;
err:
	if (errno == EINVAL)
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_ERR - 1;
}

static void
backup_make(char *R dst, const char *R src)
{
	jstr_strcpy_len(jstr_mempcpy(dst, src, jstr_strnlen(src, JSTR_IO_NAME_MAX)), ".bak", sizeof(".bak") - 1);
}

static int
file_exists(const char *R fname)
{
	return access(fname, F_OK | W_OK | R_OK) == 0;
}

static jstr_ret_ty
process_file(const jstr_twoway_ty *R t,
             jstr_ty *R buf,
             const char *R fname,
             const struct stat *st,
             const char *R find,
             const size_t find_len,
             const char *R rplc,
             const size_t rplc_len)
{
	jstr_io_ft_ty ft = jstr_io_exttype(buf->data, buf->size);
	if (ft == JSTR_IO_FT_BINARY)
		return JSTR_RET_SUCC;
	if (jstr_chk(jstr_io_readfile_len_j(buf, fname, 0, (size_t)st->st_size)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (ft == JSTR_IO_FT_UNKNOWN)
		if (jstr_isbinary(buf->data, 64, buf->size))
			return JSTR_RET_SUCC;
	size_t changed;
#if REGEX_IS_IMPLEMENTED
	if (G.regex_use) {
		const jstr_re_off_ty c = jstr_re_rplcall_len_j(&G.regex, buf, rplc, rplc_len, G.cflags);
		if (jstr_re_chk(c)) {
			jstr_re_errdie(-c, &G.regex);
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		}
		changed = (size_t)c;
	} else
#endif
	{
		const size_t c = jstr_rplcall_len_exec_j(t, buf, find, find_len, rplc, rplc_len);
		if (jstr_unlikely(c == (size_t)-1))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		changed = c;
	}
	if (!changed)
		return JSTR_RET_SUCC;
	if (G.print_mode == PRINT_STDOUT) {
		jstr_io_fwrite(buf->data, 1, buf->size, stdout);
		if (buf->size && *(buf->data + buf->size - 1) != '\n')
			jstr_io_putchar('\n');
	} else {
		if (G.print_mode == PRINT_FILE_BACKUP) {
			char bak[JSTR_IO_NAME_MAX + 4 + 1];
			backup_make(bak, fname);
			if (jstr_unlikely(file_exists(bak)))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			if (jstr_unlikely(rename(fname, bak)))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		}
		if (jstr_chk(jstr_io_fwritefile_len_j(buf, fname, "w")))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	return JSTR_RET_SUCC;
}

typedef struct args_ty {
	jstr_ty *buf;
	const char *find;
	size_t find_len;
	const char *rplc;
	size_t rplc_len;
	const jstr_twoway_ty *t;
} args_ty;

static JSTR_IO_FTW_FUNC(callback_file, ftw, args)
{
	const args_ty *const a = args;
	if (jstr_chk(process_file(a->t, a->buf, ftw->dirpath, ftw->st, a->find, a->find_len, a->rplc, a->rplc_len)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_SUCC;
}

typedef struct matcher_args_ty {
	const char *pattern;
} matcher_args_ty;

static JSTR_IO_FTW_FUNC_MATCH(matcher, fname, fname_len, args)
{
	matcher_args_ty *a = (matcher_args_ty *)args;
	if (fnmatch(a->pattern, fname, 0))
		return 1;
	return 0;
	(void)fname_len;
}

int
main(int argc, char **argv)
{
	if (jstr_nullchk(argv[1]) || jstr_nullchk(argv[2]) || jstr_nullchk(argv[3])) {
		PRINTERR("Usage: %s [FIND] [REPLACE] [OPTIONS]... [FILES]...\n"
		         "Options:\n"
		         "  -i, -i.bak\n"
		         "    Replace files in-place. The default is printing to stdout.\n"
		         "    If .bak is provided, backup the original file prefixed with .bak.\n"
		         "  -r\n"
		         "    Recurse on the arguments given if they are directories.\n"
		         "  -name pattern\n"
		         "    File pattern to match when -r is used. Pattern is a wildcard.\n"
		         "    If -name is used without -r, behavior is undefined.\n"
#if REGEX_IS_IMPLEMENTED
		         "  -regex\n"
		         "    Treat FIND as a regex pattern.\n"
		         "  -E\n"
		         "    Use POSIX Extended Regular Expressions syntax.\n"
		         "    REG_EXTENDED is passed as the cflag to regexec.\n"
		         "  -icase\n"
		         "    Ignore case if FIND is a regex pattern.\n"
		         "    REG_ICASE is passed as the cflag to regexec.\n"
#endif
		         "\n"
		         "FIND and REPLACE shall be placed in that exact order.\n"
		         "OPTIONS shall be placed before FILES.\n"
		         "\\b, \\f, \\n, \\r, \\t, \\v, and \\ooo (octal) in FIND and REPLACE will be unescaped.\n"
		         "\n"
		         "Filenames shall not start with - as they will be interpreted as a flag.",
		         argv[0]);
		return EXIT_FAILURE;
	}
	jstr_ty buf = JSTR_INIT;
	DIE_IF(jstr_chk(jstr_reserve_j(&buf, 4096)));
	struct stat st;
	int ret;
	args_ty a;
	matcher_args_ty m;
	a.find = (const char *)FIND;
	a.rplc = (const char *)RPLC;
	a.find_len = JSTR_DIFF(jstr_unescape_p(FIND), FIND);
	a.rplc_len = JSTR_DIFF(jstr_unescape_p(RPLC), RPLC);
	m.pattern = NULL;
	jstr_twoway_ty t;
	a.t = &t;
	for (unsigned int i = 3; ARG; ++i) {
		switch (argv[i][0]) {
		case '-': /* flag */
			if (!strcmp(ARG, "-i")) {
				G.print_mode = PRINT_FILE;
			} else if (!strcmp(ARG, "-i.bak")) {
				G.print_mode = PRINT_FILE_BACKUP;
			} else if (!strcmp(ARG, "-r")) {
				G.recursive = 1;
#if REGEX_IS_IMPLEMENTED
			} else if (!strcmp(ARG, "-regex")) {
				G.regex_use = 1;
			} else if (!strcmp(ARG, "-icase")) {
				G.cflags |= JSTR_RE_CF_ICASE;
			} else if (!strcmp(ARG, "-E")) {
				G.cflags |= JSTR_RE_CF_EXTENDED;
#endif
			} else if (!strcmp(ARG, "-name")) {
				++i;
				if (jstr_nullchk(ARG))
					jstr_errdie("No argument after -name flag.");
				G.file_pattern = ARG;
				m.pattern = G.file_pattern;
			}
			break;
		default:;
			if (!G.compiled) {
#if REGEX_IS_IMPLEMENTED
				if (G.regex_use)
					jstr_re_comp(&G.regex, a.find, G.cflags);
				else
#endif
					jstr_memmem_comp(&t, a.find, a.find_len);
				G.compiled = 1;
			}
			ret = xstat(ARG, &st);
			DIE_IF(ret == JSTR_RET_ERR);
			if (ret != JSTR_RET_SUCC)
				continue;
			if (IS_REG(st.st_mode)) {
				DIE_IF(jstr_chk(process_file(&t, &buf, ARG, &st, a.find, a.find_len, a.rplc, a.rplc_len)));
			} else if (IS_DIR(st.st_mode)) {
				if (G.recursive) {
					a.buf = &buf;
					DIE_IF(jstr_chk(jstr_io_ftw(ARG, callback_file, &a, JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG, G.file_pattern ? matcher : NULL, &m)));
				}
			} else {
				PRINTERR("stat() failed on %s.\n", ARG);
				exit(EXIT_FAILURE);
			}
			break;
		}
	}
#if DO_FREE /* We don't need to free since we're exiting. */
	jstr_free_j(&buf);
#endif
	return EXIT_SUCCESS;
	(void)argc;
}
