/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "files.h"
#include "process.h"

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

#if 0
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
				return FT_BINARY;
	}
	return FT_UNKNOWN;
}
#endif

/* stat() wrapper: returns JSTR_RET_ERR (instead of failing silently) on error. */
JSTR_FUNC
jstr_ret_ty
xstat(const char *R file,
        struct stat *R buf)
{
	if (jstr_unlikely(stat(file, buf)))
		goto err;
	return JSTR_RET_SUCC;
err:
	JSTR_RETURN_ERR(JSTR_RET_ERR);
}

/* True if FNAME exists at all. Used only to detect backup-name collisions;
 * access() is called with F_OK alone so read-only files still count. */
int
file_exists(const char *R fname)
{
	return access(fname, F_OK) == 0;
}

/* ftw callback: process every regular file the traversal yields. */
JSTR_IO_FTW_FUNC(callback_file, ftw, args)
{
	const args_ty *const a = args;
	if (jstr_chk(process_file(a->t, a->buf, ftw->dirpath, ftw->dirpath_len, ftw->st, a->find, a->find_len, a->rplc, a->rplc_len)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_SUCC;
}

/* ftw matcher: return 1 to skip a file. --include only admits files whose
 * basename matches its (compiled) regex; --exclude skips files whose basename
 * matches. The regexes live in the global state, compiled during flag parsing
 * or the confirm TUI, so the args pointer is unused. */
JSTR_IO_FTW_FUNC_MATCH(matcher, fname, fname_len, args)
{
	if (G.have_include)
		if (jstr_re_match_len(&G.include_re, fname, fname_len, 0) != JSTR_RE_RET_NOERROR)
			return 1;
	if (G.have_exclude)
		if (jstr_re_match_len(&G.exclude_re, fname, fname_len, 0) == JSTR_RE_RET_NOERROR)
			return 1;
	return 0;
	(void)args;
}
