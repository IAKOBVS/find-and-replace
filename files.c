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
 * basename matches; --exclude skips files whose basename matches. */
JSTR_IO_FTW_FUNC_MATCH(matcher, fname, fname_len, args)
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

int
file_matches_filter(const char *R fname, size_t fname_len, const char *R filter, size_t filter_len)
{
	if (filter_len == 0 || filter == NULL)
		return 1;

	const char *basename = (const char *)jstr_memrchr(fname, '/', fname_len);
	basename = (basename != NULL && *(basename + 1) != '\0') ? basename + 1 : fname;

	size_t pos = 0;
	while (pos < filter_len) {
		/* Skip whitespace */
		while (pos < filter_len && (filter[pos] == ' ' || filter[pos] == '\t'))
			pos++;
		if (pos >= filter_len)
			break;

		size_t tok_start = pos;
		while (pos < filter_len && filter[pos] != ' ' && filter[pos] != '\t')
			pos++;
		size_t tok_len = pos - tok_start;
		if (tok_len == 0)
			continue;

		const char *tok = filter + tok_start;

		/* Check --include */
		if (tok_len == S_LEN("--include") && memcmp(tok, S_LITERAL("--include")) == 0) {
			while (pos < filter_len && (filter[pos] == ' ' || filter[pos] == '\t'))
				pos++;
			size_t glob_start = pos;
			while (pos < filter_len && filter[pos] != ' ' && filter[pos] != '\t')
				pos++;
			size_t glob_len = pos - glob_start;
			if (glob_len > 0) {
				char glob_buf[256];
				if (glob_len < sizeof(glob_buf)) {
					memcpy(glob_buf, filter + glob_start, glob_len);
					glob_buf[glob_len] = '\0';
					if (fnmatch(glob_buf, fname, 0) != 0 && fnmatch(glob_buf, basename, 0) != 0)
						return 0;
				}
			}
			continue;
		} else if (tok_len > S_LEN("--include=") && memcmp(tok, S_LITERAL("--include=")) == 0) {
			const char *glob = tok + S_LEN("--include=");
			size_t glob_len = tok_len - S_LEN("--include=");
			char glob_buf[256];
			if (glob_len < sizeof(glob_buf)) {
				memcpy(glob_buf, glob, glob_len);
				glob_buf[glob_len] = '\0';
				if (fnmatch(glob_buf, fname, 0) != 0 && fnmatch(glob_buf, basename, 0) != 0)
					return 0;
			}
			continue;
		}

		/* Check --exclude */
		if (tok_len == S_LEN("--exclude") && memcmp(tok, S_LITERAL("--exclude")) == 0) {
			while (pos < filter_len && (filter[pos] == ' ' || filter[pos] == '\t'))
				pos++;
			size_t glob_start = pos;
			while (pos < filter_len && filter[pos] != ' ' && filter[pos] != '\t')
				pos++;
			size_t glob_len = pos - glob_start;
			if (glob_len > 0) {
				char glob_buf[256];
				if (glob_len < sizeof(glob_buf)) {
					memcpy(glob_buf, filter + glob_start, glob_len);
					glob_buf[glob_len] = '\0';
					if (fnmatch(glob_buf, fname, 0) == 0 || fnmatch(glob_buf, basename, 0) == 0)
						return 0;
				}
			}
			continue;
		} else if (tok_len > S_LEN("--exclude=") && memcmp(tok, S_LITERAL("--exclude=")) == 0) {
			const char *glob = tok + S_LEN("--exclude=");
			size_t glob_len = tok_len - S_LEN("--exclude=");
			char glob_buf[256];
			if (glob_len < sizeof(glob_buf)) {
				memcpy(glob_buf, glob, glob_len);
				glob_buf[glob_len] = '\0';
				if (fnmatch(glob_buf, fname, 0) == 0 || fnmatch(glob_buf, basename, 0) == 0)
					return 0;
			}
			continue;
		}

		/* Check negation !pattern */
		if (tok[0] == '!' && tok_len > 1) {
			const char *pat = tok + 1;
			size_t pat_len = tok_len - 1;
			char pat_buf[256];
			if (pat_len < sizeof(pat_buf)) {
				memcpy(pat_buf, pat, pat_len);
				pat_buf[pat_len] = '\0';
				if (fnmatch(pat_buf, fname, 0) == 0 || fnmatch(pat_buf, basename, 0) == 0 || jstr_strstr_len(fname, fname_len, pat, pat_len) != NULL)
					return 0;
			}
			continue;
		}

		/* Check if token has glob wildcards (*, ?, [) */
		int is_glob = 0;
		for (size_t g_i = 0; g_i < tok_len; ++g_i) {
			if (tok[g_i] == '*' || tok[g_i] == '?' || tok[g_i] == '[') {
				is_glob = 1;
				break;
			}
		}

		char tok_buf[256];
		if (tok_len < sizeof(tok_buf)) {
			memcpy(tok_buf, tok, tok_len);
			tok_buf[tok_len] = '\0';
			if (is_glob) {
				if (fnmatch(tok_buf, fname, 0) != 0 && fnmatch(tok_buf, basename, 0) != 0)
					return 0;
			} else {
				if (jstr_strstr_len(fname, fname_len, tok, tok_len) == NULL)
					return 0;
			}
		}
	}

	return 1;
}
