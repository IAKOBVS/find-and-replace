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

#include <jstr/jstr.h>
#include <jstr/jstr-io.h>
#include <jstr/jstr-regex.h>
#include <fnmatch.h>

#define DIE_IF_PRINT(x, msg)              \
	do {                              \
		if (jstr_unlikely(x))     \
			jstr_errdie(msg); \
	} while (0)
#define DIE_IF(x)   DIE_IF_PRINT(x, "")
#define DIE()       DIE_IF(1)
#define ARG         argv[i]
#define ARG_NEXT()  ++i
#define unlikely(x) jstr_unlikely(x)
#define IS_REG(x)   S_ISREG(x)
#define IS_DIR(x)   S_ISDIR(x)
#define FIND        argv[1]
#define RPLC        argv[2]
#define R           JSTR_RESTRICT

#define _(x) x
#define SEP  '/'

#define DO_FREE 0

typedef enum {
	PRINT_STDOUT = 0,
	PRINT_FILE,
	PRINT_FILE_BACKUP,
} print_mode_ty;

typedef struct global_ty {
	const char *include_glob;
	int have_files;
	int print_mode;
	int recursive;
	int compiled;
	int regex_use;
	int cflags;
	regex_t regex;
	const char *bak_suffix;
	size_t bak_suffix_len;
	char bak[JSTR_IO_PATH_MAX];
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
	if (jstr_unlikely(errno == EINVAL))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_ERR - 1;
}

static int
file_exists(const char *R fname)
{
	return access(fname, F_OK | W_OK | R_OK) == 0;
}

typedef enum {
	/* Unknown file type. */
	FT_UNKNOWN = 0,
#define FT_UNKNOWN FT_UNKNOWN
	/* Text file type. */
	FT_TEXT,
#define FT_TEXT FT_TEXT
	/* Binary file type. */
	FT_BINARY
#define FT_BINARY FT_BINARY
} ft_ty;

static ft_ty
exttype(const char *fname, size_t fname_len)
{
	fname = jstr_memrchr(fname, '.', fname_len);
	if (fname != NULL && *++fname != '\0') {
		static const char *textv[] = { "C", "S", "c", "cc", "cs", "cpp", "h", "hh", "hpp", "html", "js", "json", "md", "pl", "pm", "py", "pyi", "rs", "s", "sh", "ts", "txt" };
		static const char *binv[] = { "a", "bin", "gz", "jpg", "jpeg", "mp4", "mp3", "mkv", "o", "pdf", "png", "pyc", "rar", "so", "wav", "zip" };
		unsigned int i;
		for (i = 0; i < sizeof(textv) / sizeof(*textv); ++i)
			if (!jstr_strcmpeq_loop(fname, textv[i]))
				return FT_TEXT;
		for (i = 0; i < sizeof(binv) / sizeof(*binv); ++i)
			if (!jstr_strcmpeq_loop(fname, binv[i]))
				return FT_TEXT;
	}
	return FT_UNKNOWN;
}

static jstr_ret_ty
process_buffer(const jstr_twoway_ty *R t,
               jstr_ty *R buf,
               const char *R fname,
               size_t fname_len,
               const struct stat *st,
               const char *R find,
               const size_t find_len,
               const char *R rplc,
               const size_t rplc_len)
{
	size_t changed;
	if (G.regex_use) {
		const jstr_re_off_ty ret = jstr_re_rplcall_backref_len_exec_j(&G.regex, buf, rplc, rplc_len, G.cflags, 10);
		if (jstr_re_chk(ret)) {
			jstr_re_errdie(-ret, &G.regex);
			return JSTR_RET_ERR;
		}
		changed = (size_t)ret;
	} else {
		const size_t ret = jstr_rplcall_len_exec_j(t, buf, find, find_len, rplc, rplc_len);
		if (jstr_unlikely(ret == (size_t)-1))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
		changed = ret;
	}
	if (G.print_mode == PRINT_STDOUT) {
		write(STDOUT_FILENO, buf->data, buf->size);
	} else {
		if (changed == 0)
			return JSTR_RET_SUCC;
		int o_creat = 0;
		if (G.print_mode == PRINT_FILE_BACKUP) {
			if (jstr_unlikely(fname_len + G.bak_suffix_len >= sizeof(G.bak))) {
				jstr_errdie("Suffix length is too large to create a backup file.");
				return JSTR_RET_ERR;
			}
			char *p = jstr_mempcpy(G.bak, fname, fname_len);
			jstr_strcpy_len(p, G.bak_suffix, G.bak_suffix_len);
			if (jstr_unlikely(file_exists(G.bak))) {
				jstr_errdie("Can't make a backup file because suffixed filename already exists.");
				return JSTR_RET_ERR;
			}
			if (jstr_unlikely(rename(fname, G.bak)))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			o_creat = O_CREAT;
		}
		if (jstr_chk(jstr_io_writefile_len_j(buf, fname, o_creat | O_TRUNC | O_WRONLY, st->st_mode & (S_IRWXO | S_IRWXG | S_IRWXU))))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	return JSTR_RET_SUCC;
}

static jstr_ret_ty
process_file(const jstr_twoway_ty *R t,
             jstr_ty *R buf,
             const char *R fname,
             size_t fname_len,
             const struct stat *st,
             const char *R find,
             const size_t find_len,
             const char *R rplc,
             const size_t rplc_len)
{
	const ft_ty ft = exttype(fname, fname_len);
	if (ft == FT_BINARY)
		return JSTR_RET_SUCC;
	if (jstr_chk(jstr_io_readfile_len_j(buf, fname, 0, (size_t)st->st_size)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (ft == FT_UNKNOWN)
		if (jstr_isbinary(buf->data, buf->size, 64))
			return JSTR_RET_SUCC;
	return process_buffer(t, buf, fname, fname_len, st, find, find_len, rplc, rplc_len);
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
	if (jstr_chk(process_file(a->t, a->buf, ftw->dirpath, ftw->dirpath_len, ftw->st, a->find, a->find_len, a->rplc, a->rplc_len)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_SUCC;
}

typedef struct matcher_args_ty {
	const char *include_glob;
	const char *exclude_glob;
} matcher_args_ty;

static JSTR_IO_FTW_FUNC_MATCH(matcher, fname, fname_len, args)
{
	matcher_args_ty *a = (matcher_args_ty *)args;
	if (a->include_glob)
		if (fnmatch(a->include_glob, fname, 0))
			return 1;
	if (a->exclude_glob)
		if (!fnmatch(a->exclude_glob, fname, 0))
			return 1;
	return 0;
	(void)fname_len;
}

static jstr_ret_ty
compile(jstr_twoway_ty *R t, const char *R find, size_t find_len)
{
	if (!G.compiled) {
		if (G.regex_use) {
			const int ret = jstr_re_comp(&G.regex, find, G.cflags);
			if (jstr_unlikely(ret != JSTR_RE_RET_NOERROR)) {
				jstr_re_errdie(-ret, &G.regex);
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
		} else {
			jstr_memmem_comp(t, find, find_len);
		}
		G.compiled = 1;
	}
	return JSTR_RET_SUCC;
}

int
main(int argc, char **argv)
{
	if (jstr_nullchk(argv[1]) || jstr_nullchk(argv[2])) {
		fprintf(stderr,
		        _("Usage: find-and-replace [FIND] [REPLACE] [OPTIONS]... [FILES]...\n")
		        _("Options:\n")
		        _("  -i[SUFFIX]\n")
		        _("    Replace files in-place. The default is printing to stdout.\n")
		        _("    If SUFFIX is provided, backup the original file suffixed with SUFFIX.\n")
		        _("  -r\n")
		        _("    Recurse on the directories in FILES.\n")
		        _("  --include GLOB\n")
		        _("    File glob to match when -r is used. Glob is a wildcard.\n")
		        _("  --exclude GLOB\n")
		        _("    The reverse of --include. Skip files that match glob.\n")
		        _("    This applies to the passed command line files.\n")
		        _("  -F\n")
		        _("    Treat FIND as a fixed-string. This is the default.\n")
		        _("  -R\n")
		        _("    Treat FIND as a regex include_glob.\n")
		        _("  -E\n")
		        _("    Use POSIX Extended Regular Expressions syntax.\n")
		        _("    REG_EXTENDED is passed as the cflag to regexec.\n")
		        _("  -I\n")
		        _("    Ignore case if FIND is a regex include_glob.\n")
		        _("    REG_ICASE is passed as the cflag to regexec.\n")
		        _("\n")
		        _("FIND and REPLACE shall be placed in that exact order.\n")
		        _("\n")
		        _("\\b, \\f, \\n, \\r, \\t, \\v, and \\ooo (octal) in FIND and REPLACE will be unescaped.\n")
		        _("Otherwise, unescaped backslashes will be removed, so use two backslashes for a backslash.\n")
		        _("For example: '\\\\(this\\\\)' and '\\\\1' instead of '\\(this\\)' and '\\1', unlike what\n")
		        _("you would do with sed.\n")
		        _("\n")
		        _("Filenames shall not start with - as they will be interpreted as a flag.\n")
		        _("\n")
		        _("Single character flags starting with a single dash can be combined.\n")
		        _("For example: -EI is equal to -E -i.\n")
		        _("\n")
		        _("-E (Extended Regex) and -I (ignore case) imply -R (Regex), so using -E or -I automatically\n")
		        _("enables -R.\n")
		        _("\n")
		        _("If no file was passed, read from stdin.\n"));
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
	m.include_glob = NULL;
	m.exclude_glob = NULL;
	jstr_twoway_ty t;
	a.t = &t;
	/* Parse all flags. */
	for (unsigned int i = 3; ARG; ++i) {
		if (*ARG == '-') {
			/* -i[SUFFIX] */
			if (ARG[1] == 'i') {
				if (ARG[2] == '\0') {
					G.print_mode = PRINT_FILE;
				} else {
					G.bak_suffix = ARG + sizeof("-i") - 1;
					G.bak_suffix_len = strlen(G.bak_suffix);
					G.print_mode = PRINT_FILE_BACKUP;
				}
				/* -- flag */
			} else if (ARG[1] == '-') {
				/* --include */
				if (!strcmp(ARG + 2, "include")) {
					ARG_NEXT();
					if (jstr_nullchk(ARG))
						jstr_errdie("No argument after --include flag.");
					m.include_glob = ARG;
					/* --exclude */
				} else if (!strcmp(ARG + 2, "exclude")) {
					ARG_NEXT();
					if (jstr_nullchk(ARG))
						jstr_errdie("No argument after --exclude flag.");
					m.exclude_glob = ARG;
				}
				/* - flags */
			} else {
				const char *argp = ARG + 1;
				/* Allow flag combinations. */
				for (; *argp; ++argp) {
					/* -r */
					if (*argp == 'r') {
						G.recursive = 1;
						/* -R */
					} else if (*argp == 'R') {
						G.regex_use = 1;
						/* -I */
					} else if (*argp == 'I') {
						G.regex_use = 1;
						G.cflags |= JSTR_RE_CF_ICASE;
						/* -E */
					} else if (*argp == 'E') {
						G.regex_use = 1;
						G.cflags |= JSTR_RE_CF_EXTENDED;
					}
				}
			}
			break;
		}
	}
	/* Parse all files/directories. */
	for (unsigned int i = 3; ARG; ++i) {
		if (*ARG != '-') {
			DIE_IF(jstr_chk(compile(&t, a.find, a.find_len)));
			ret = xstat(ARG, &st);
			DIE_IF(ret == JSTR_RET_ERR);
			if (ret != JSTR_RET_SUCC)
				continue;
			if (IS_REG(st.st_mode)) {
				const size_t fname_len = strlen(ARG);
				G.have_files = 1;
				if (!m.exclude_glob) {
process:
					DIE_IF(jstr_chk(process_file(&t, &buf, ARG, fname_len, &st, a.find, a.find_len, a.rplc, a.rplc_len)));
				} else {
					const char *fname = jstr_memrchr(ARG, SEP, fname_len);
					/* Get the filename. */
					fname = (fname != NULL && *(fname + 1)) ? fname + 1 : ARG;
					if (!fnmatch(m.exclude_glob, fname, 0))
						goto process;
				}
			} else if (IS_DIR(st.st_mode)) {
				G.have_files = 1;
				if (G.recursive) {
					a.buf = &buf;
					DIE_IF(jstr_chk(jstr_io_ftw(ARG, callback_file, &a, JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG, G.include_glob ? matcher : NULL, &m)));
				}
			} else {
				fprintf(stderr, "stat() failed on %s.\n", ARG);
				exit(EXIT_FAILURE);
			}
			break;
		}
	}
	/* If no file is passed, read from stdin. */
	if (!G.have_files) {
		if (jstr_unlikely(G.bak_suffix != NULL) || jstr_unlikely(G.print_mode != PRINT_STDOUT)) {
			jstr_err("Trying to create a backup file while reading from stdin.");
			DIE();
		}
		if (jstr_unlikely(G.recursive)) {
			jstr_err("Trying to recursively traverse through directories while reading from stdin.");
			DIE();
		}
		jstr_io_readstdin_j(&buf);
		DIE_IF(jstr_chk(compile(&t, a.find, a.find_len)));
		DIE_IF(jstr_chk(process_buffer(&t, &buf, NULL, 0, NULL, a.find, a.find_len, a.rplc, a.rplc_len)));
	}
#if DO_FREE /* We don't need to free since we're exiting. */
	jstr_free_j(&buf);
#endif
	return EXIT_SUCCESS;
	(void)argc;
}
