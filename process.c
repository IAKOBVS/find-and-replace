/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "process.h"
#include "files.h"
#include "confirm.h"

/* Number of leading bytes scanned for NULs when deciding a file is binary;
 * covers the usual text/binary header region without reading the whole file. */
#define BINARY_SCAN_SIZE (JSTR_IO_KIB * 4)

/* Print the "FNAME:LINE:PREFIX" prefix of one -c preview line. */
static jstr_ret_ty
print_line_prefix(const char *R fname, size_t fname_len, size_t line)
{
	if (jstr_unlikely(jstr_io_fwrite(COLOR_RED, 1, S_LEN(COLOR_RED), stdout)) != S_LEN(COLOR_RED))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (jstr_unlikely(jstr_io_fwrite(fname, 1, fname_len, stdout) != fname_len))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (jstr_unlikely(jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout)) != S_LEN(COLOR_RESET))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (jstr_unlikely(jstr_io_fputc(':', stdout) == EOF))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (jstr_unlikely(jstr_io_fwrite(COLOR_GREEN, 1, S_LEN(COLOR_GREEN), stdout)) != S_LEN(COLOR_GREEN))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	print_size_t(line);
	if (jstr_unlikely(jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout)) != S_LEN(COLOR_RESET))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (jstr_unlikely(jstr_io_fputc(':', stdout) == EOF))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	return JSTR_RET_SUCC;
}

/* --grep mode: print the whole content of every line that matches FIND.
 * Matching is line-based like grep (a regex can never span newlines here,
 * unlike the replace path which scans the whole buffer). A fixed-string
 * empty find matches every line, mirroring grep ''. */
jstr_ret_ty
grep_scan_file(const jstr_ty *R buf, const char *R fname, size_t fname_len,
               const char *R find, size_t find_len)
{
	const char *d = buf->data;
	const size_t n = buf->size;
	const char *p = d;
	for (size_t line = 1;; ++line) {
		const char *nl = memchr(p, '\n', (size_t)(d + n - p));
		const size_t line_len = (nl != NULL) ? (size_t)(nl - p) : (size_t)(d + n - p);
		int matched = 0;
		regmatch_t rm = { 0 };
		if (G.mode & MODE_USE_REGEX) {
			matched = (jstr_re_search_len(&G.regex, p, line_len, &rm, G.eflags) == JSTR_RE_RET_NOERROR);
		} else {
			if (find_len) {
				const char *tmp = jstr_strstr_len(p, line_len, find, find_len);
				if (tmp) {
					matched = 1;
					rm.rm_so = tmp - p;
				}
			}
			if (find_len)
				rm.rm_eo = (size_t)rm.rm_so + find_len;
		}
		if (matched) {
			G.grep_matched = 1;
			if (!(G.mode & MODE_QUIET)) {
				if (jstr_likely(fname != NULL))
					print_line_prefix(fname, fname_len, line);
#if 0
				if (jstr_unlikely(jstr_io_fwrite(p, 1, line_len, stdout) != line_len))
					JSTR_RETURN_ERR(JSTR_RET_ERR);
#else
				if (jstr_unlikely(jstr_io_fwrite(p, 1, (size_t)rm.rm_so, stdout) != (size_t)rm.rm_so))
					JSTR_RETURN_ERR(JSTR_RET_ERR);
				if (jstr_unlikely(jstr_io_fwrite(COLOR_RED, 1, S_LEN(COLOR_RED), stdout) != S_LEN(COLOR_RED)))
					JSTR_RETURN_ERR(JSTR_RET_ERR);
				if (jstr_unlikely(jstr_io_fwrite(p + rm.rm_so, 1, (size_t)(rm.rm_eo - rm.rm_so), stdout) != (size_t)(rm.rm_eo - rm.rm_so)))
					JSTR_RETURN_ERR(JSTR_RET_ERR);
				if (jstr_unlikely(jstr_io_fwrite(COLOR_RESET, 1, S_LEN(COLOR_RESET), stdout) != S_LEN(COLOR_RESET)))
					JSTR_RETURN_ERR(JSTR_RET_ERR);
				if (jstr_unlikely(jstr_io_fwrite(p + rm.rm_eo, 1, line_len - (size_t)rm.rm_eo, stdout) != line_len - (size_t)rm.rm_eo))
					JSTR_RETURN_ERR(JSTR_RET_ERR);
#endif
				if (jstr_unlikely(jstr_io_fputc('\n', stdout) == EOF))
					JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
		}
		if (nl == NULL)
			break;
		p = nl + 1;
	}
	return JSTR_RET_SUCC;
}

jstr_ret_ty
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
	/* Holds the length of the replaced output. As a size_t when the fixed
	 * and regex paths both store a length; the regex variant returns a
	 * signed offset type that may hold a negative error code. */
	union u {
		size_t zu;
		jstr_re_off_ty d;
	} changed;
	int fd_tmp = -1;
	char *bakp = NULL;
	char bak[JSTR_IO_PATH_MAX];
	if (G.mode & MODE_USE_REGEX) {
		/* Temporarily remove trailing newline. */
		if (buf->size && buf->data[buf->size - 1] == '\n') {
			buf->data[buf->size - 1] = '\0';
			--buf->size;
		}
		/* The regex engine rejects empty patterns, so short-circuit them. */
		if (jstr_unlikely(find_len == 0)) {
			changed.zu = 0;
		} else {
			changed.d = jstr_re_rplcn_backref_len_exec_j(&G.regex, buf, rplc, rplc_len, G.eflags, JSTR_NMATCH_MAX, G.n);
			if (jstr_re_chk(changed.d)) {
				jstr_re_errdie(changed.d, &G.regex, "%s", "Regex replacement failed.\n");
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			changed.zu = (size_t)changed.d;
		}
	} else {
		/* Fixed-string path uses the precompiled Two-Way matcher. */
		changed.zu = jstr_rplcn_len_exec_j(t, buf, find, find_len, rplc, rplc_len, G.n);
		if (jstr_unlikely(changed.zu == (size_t)-1))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	/* Append newline if has space */
	/* Keep the final buffer newline-terminated so file output ends cleanly. */
	if (buf->size && buf->data[buf->size - 1] != '\n')
		DIE_IF(jstr_pushback_j(buf, '\n'), "%s", "Out of memory.\n");
	if (G.mode & MODE_PRINT_STDOUT) {
		/* Default mode: write the (replaced) buffer to stdout. */
		if (jstr_unlikely(jstr_io_fwrite(buf->data, 1, buf->size, stdout) != buf->size))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	} else {
		/* In-place mode (-i): nothing to do if nothing changed. */
		if (changed.zu == 0)
			return JSTR_RET_SUCC;
		if (G.mode & MODE_PRINT_FILE_BACKUP) {
			/* -iSUFFIX: rename the original aside, then write the new file. */
			if (jstr_unlikely(fname_len + G.bak_suffix_len >= sizeof(bak))) {
				jstr_errdie("Suffix length is too large to create a backup file (%zu >= %zu).\n", fname_len + G.bak_suffix_len, sizeof(bak));
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			char *p = jstr_mempcpy(bak, fname, fname_len);
			jstr_strcpy_len(p, G.bak_suffix, G.bak_suffix_len);
			if (jstr_unlikely(file_exists(bak))) {
				jstr_errdie("Can't make a backup file because suffixed filename (%s) already exists.\n", bak);
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			if (jstr_unlikely(rename(fname, bak)))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			if (jstr_chk(jstr_io_writefile_len_j(buf, fname, O_CREAT | O_TRUNC | O_WRONLY, st->st_mode & (S_IRWXO | S_IRWXG | S_IRWXU))))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		} else {
			/* Plain -i: write to a temp file next to the original, then
			 * rename it over the original for an atomic replace. */
			bakp = bak;
			if (jstr_unlikely(fname_len + S_LEN(".XXXXXX") >= sizeof(bak))) {
				jstr_errdie("Filename (%s) is too large to create a backup file (%zu >= %zu).\n", fname, fname_len + S_LEN(".XXXXXX"), sizeof(bak));
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			char *p = jstr_mempcpy(bak, fname, fname_len);
			p = jstr_stpcpy_len(p, S_LITERAL(".XXXXXX"));
			fd_tmp = mkstemp(bak);
			if (jstr_unlikely(fd_tmp == -1)) {
				bakp = NULL;
				jstr_errdie("Can't make a file (%s) to temporarily write replacements to.\n", bak);
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			if (jstr_chk(jstr_io_writefilefd_len_j(buf, fd_tmp))) {
				jstr_errdie("Can't write replacements to temp file (%s).\n", bak);
				goto err;
			}
			if (jstr_unlikely(close(fd_tmp) == -1)) {
				fd_tmp = -1;
				jstr_errdie("Can't close temp file (%s).\n", bak);
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			fd_tmp = -1;
			if (jstr_unlikely(rename(bak, fname))) {
				jstr_errdie("Can't rename temp file (%s) to original file (%s).\n", bak, fname);
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			bakp = NULL;
		}
		/* The file was successfully rewritten in place: report its name on
		 * stderr (never stdout) so the caller can see what changed. -q
		 * silences this echo; -l still prints it to stdout explicitly. */
		if (!(G.mode & MODE_QUIET)) {
			if (jstr_unlikely(jstr_io_fwrite(fname, 1, fname_len, stderr) != fname_len))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			if (jstr_unlikely(jstr_io_fputc('\n', stderr) == EOF))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		}
		if (G.mode & MODE_PRINT_CHANGES) {
			if (jstr_unlikely(jstr_io_fwrite(fname, 1, fname_len, stdout) != fname_len))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			if (jstr_chk(jstr_io_putchar('\n')))
				JSTR_RETURN_ERR(JSTR_RET_ERR);
		}
	}
	return JSTR_RET_SUCC;
err:
	if (fd_tmp != -1)
		if (close(fd_tmp) < 0) {}
	if (bakp != NULL)
		if (unlink(bakp) < 0) {}
	return JSTR_RET_ERR;
}

jstr_ret_ty
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
	const size_t file_size = (size_t)st->st_size;
	/* A fixed-string find longer than the whole file cannot match. In the
	 * interactive editor the find can still be edited to something shorter,
	 * so keep such files cached there. */
	if (!(G.mode & MODE_USE_REGEX) && file_size < find_len &&
	    !((G.mode & MODE_CONFIRM) && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)))
		return JSTR_RET_SUCC;
	/* Preallocate the length of the replace string. */
	/* Worst-case output size = input + (longer replace) + trailing newline. */
	if (rplc_len > find_len && !(G.mode & MODE_USE_REGEX))
		if (jstr_chk(jstr_reserve_j(buf, file_size + rplc_len - find_len + S_LEN("\n") + 1)))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (jstr_chk(jstr_io_readfile_len_j(buf, fname, 0, file_size)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);
	/* Skip files with NUL bytes in the first BINARY_SCAN_SIZE bytes. */
	if (jstr_io_isbinary_atleast(buf->data, file_size, BINARY_SCAN_SIZE))
		return JSTR_RET_SUCC;
	/* --grep mode never edits; scan and print matching lines instead. */
	if (G.mode & MODE_GREP)
		return grep_scan_file(buf, fname, fname_len, find, find_len);
	/* During the -c dry-run pass, only scan and preview; the real edit
	 * happens on the second pass after the user confirms. The file's content
	 * is recorded so pass 2 edits it from memory without re-reading disk. */
	if (G.confirm_pass && (G.mode & MODE_CONFIRM)) {
		/* Interactive mode: pass 1 only caches files. The confirm TUI scans
		 * each cached buffer live (bounded to the preview budget) on every
		 * redraw, so a pre-scan here would both dump the whole diff to stdout
		 * before the editor opens and, with -g on a large tree, stall the
		 * startup on an unbounded match collection. */
		if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
			file_pushback(&G.files, fname, fname_len, st, buf);
			return JSTR_RET_SUCC;
		}
		size_t matches = 0;
		jstr_ret_ty ret = confirm_scan_file(t, buf, fname, fname_len, find, find_len, rplc, rplc_len, &matches);
		/* Only files with matches need editing on pass 2; steal their buffer. */
		if (matches > 0)
			file_pushback(&G.files, fname, fname_len, st, buf);
		return ret;
	}
	jstr_ret_ty ret = process_buffer(t, buf, fname, fname_len, st, find, find_len, rplc, rplc_len);
	return ret;
}
