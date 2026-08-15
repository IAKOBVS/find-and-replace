/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "files.h"
#include "process.h"
#include "confirm.h"

#define IS_REG(x) S_ISREG(x)
#define IS_DIR(x) S_ISDIR(x)
#define ARG                 argv[i]
#define ARG_NEXT()          ++i
#define ARG_PREV()          --i
#define FIND                argv[1]
#define RPLC                argv[2]
#define SEP                 '/'

#define VERSION             "0.1.0"

#define _(x) x

global_ty G = { .mode = MODE_PRINT_STDOUT };

/* clang-format off */

static const char *usage =
	_("Usage: find-and-replace [FIND] [REPLACE] [OPTIONS]... [FILES]...\n")
	_("Options:\n")
	_("  -G (default)\n")
	_("    Replace first occurrence of FIND with REPLACE.\n")
	_("  -g\n")
	_("    Replace all occurrences of FIND with REPLACE, negates -G flag.\n")
	_("  -i[SUFFIX]\n")
	_("    Replace files in-place. The default is printing to stdout.\n")
	_("    If SUFFIX is provided, backup the original file suffixed with SUFFIX.\n")
	_("  -c\n")
	_("    Confirm mode. Dry-run scans the files and prints each removed line\n")
	_("    prefixed with file:line:- in red and each replacement line prefixed\n")
	_("    with file:line:+ in green. Prompts for confirmation ('y') before\n")
	_("    modifying files in-place. Requires -i and at least one file. When\n")
	_("    run on a terminal, an interactive editor lets you tweak FIND,\n")
	_("    REPLACE, flags, the file filter, --include/--exclude regexes and the\n")
	_("    backup suffix before confirming.\n")
	_("  -r\n")
	_("    Recurse on the directories in FILES.\n")
	_("  --include REGEX\n")
	_("    Only process files whose basename matches REGEX when -r is used.\n")
	_("    The pattern is a POSIX regex (BRE by default; -E/-I apply).\n")
	_("  --exclude REGEX\n")
	_("    The reverse of --include. Skip files whose basename matches REGEX.\n")
	_("    This applies to the passed command line files as well.\n")
	_("  -F (default)\n")
	_("    Treat FIND as a fixed-string.\n")
	_("  -R\n")
	_("    Treat FIND as a regex, negates -F flag.\n")
	_("  -E\n")
	_("    Use POSIX Extended Regular Expressions syntax.\n")
	_("    REG_EXTENDED is passed as the cflag to regexec.\n")
	_("  -I\n")
	_("    Ignore case.\n")
	_("    REG_ICASE is passed as the cflag to regexec.\n")
	_("  -Z (default)\n")
	_("    Anchors match newlines.\n")
	_("    REG_NEWLINE is passed as the cflag to regexec.\n")
	_("  -z\n")
	_("    Anchors only match the start or end of the string not newlines, negates -Z flag.\n")
	_("    You can still use newlines in the FIND string, different from sed.\n")
	_("    REG_NEWLINE is not passed as the cflag to regexec.\n")
	_("  -v, --version\n")
	_("    Print version information and exit.\n")
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
	_("For example: -EI is equal to -E -I.\n")
	_("\n")
	_("-E (Extended Regex) and -I (ignore case) imply -R (Regex), so using -E or -I automatically\n")
	_("enables -R.\n")
	_("\n")
	_("If no file was passed, read from stdin.\n");

/* clang-format on */

/* Compile FIND (regex or Two-Way fixed-string matcher) into the global
 * state. Recompiles when the regex mode/cflags change between files; the
 * MODE_COMPILED bit alone cannot guard that, since -R/-E/-F may appear
 * anywhere on the command line, even after a file argument. */
static jstr_ret_ty
compile(jstr_twoway_ty *R t, const jstr_literal_ty *find, const jstr_literal_ty *rplc)
{
	const int want_regex = (G.mode & MODE_USE_REGEX) != 0;
	if (!(G.mode & MODE_COMPILED) || want_regex != G.compiled_regex || (want_regex && G.cflags != G.compiled_cflags)) {
		if (G.mode & MODE_COMPILED) {
			if (G.compiled_regex)
				jstr_re_free(&G.regex);
			G.mode &= ~MODE_COMPILED;
		}
		if (want_regex) {
			const int ret = jstr_re_comp(&G.regex, find->data, G.cflags);
			if (jstr_unlikely(ret != JSTR_RE_RET_NOERROR)) {
				jstr_re_err(ret, &G.regex, "regex compilation failed for pattern \"%s\".\n", find->data);
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			/* Validate backreferences */
			size_t max_backref = 0;
			for (size_t idx = 0; idx + 1 < rplc->size; ++idx) {
				if (rplc->data[idx] == '\\' && rplc->data[idx+1] >= '1' && rplc->data[idx+1] <= '9') {
					size_t num = rplc->data[idx+1] - '0';
					if (num > max_backref)
						max_backref = num;
					++idx;
				}
			}
			if (jstr_unlikely(max_backref > G.regex.reg.re_nsub)) {
				fprintf(stderr, "find-and-replace error: Replace backreference \\%zu exceeds find capture groups (%zu)\n", max_backref, G.regex.reg.re_nsub);
				exit(EXIT_FAILURE);
			}
		} else {
			jstr_memmem_comp(t, find->data, find->size);
		}
		G.compiled_regex = want_regex;
		G.compiled_cflags = G.cflags;
		G.mode |= MODE_COMPILED;
	}
	return JSTR_RET_SUCC;
}

/* Default flags. */
static void
init_defaults()
{
	/* Anchors match on newlines. */
	G.cflags |= JSTR_RE_CF_NEWLINE;
	/* Non-global replacement. */
	G.n = 1;
}

/* Return 1 if FILE passes the -c confirm filters: the interactive Files
 * substring filter, the --include regex and the --exclude regex (both
 * compiled into the global state by the flag parser or the confirm TUI). */
static int
file_filter_pass(const file_ty *R file, const jstr_ty *R files_buf)
{
	if (files_buf->size > 0 && files_buf->data) {
		if (jstr_strstr_len(file->fname, file->fname_len, files_buf->data, files_buf->size) == NULL)
			return 0;
	}
	/* Include/Exclude regexes match against the basename, like the flag
	 * parser and the ftw matcher. */
	const char *base = jstr_memrchr(file->fname, SEP, file->fname_len);
	base = (base != NULL && *(base + 1)) ? base + 1 : file->fname;
	const size_t base_len = (size_t)(file->fname + file->fname_len - base);
	if (G.have_include)
		if (jstr_re_match_len(&G.include_re, base, base_len, 0) != JSTR_RE_RET_NOERROR)
			return 0;
	if (G.have_exclude)
		if (jstr_re_match_len(&G.exclude_re, base, base_len, 0) == JSTR_RE_RET_NOERROR)
			return 0;
	return 1;
}

static void
cleanup()
{
#if DO_FREE /* We don't need to free since we're exiting. */
	for (unsigned int i = 0; i < G.files.size; ++i) {
		free(G.files.data[i].content.data);
		free(G.files.data[i].fname);
	}
	free(G.files.data);
	free(G.matches.data);
	jstr_re_free(&G.regex);
	if (G.have_include)
		jstr_re_free(&G.include_re);
	if (G.have_exclude)
		jstr_re_free(&G.exclude_re);
	jstr_free_j(&G.rplc_buf);
	jstr_free_j(&G.new_buf);
	jstr_free_j(&G.content_buf);
	jstr_free_j(&G.interactive_find_buf);
	jstr_free_j(&G.interactive_rplc_buf);
	jstr_free_j(&G.interactive_flags_buf);
	jstr_free_j(&G.interactive_files_buf);
	jstr_free_j(&G.interactive_include_buf);
	jstr_free_j(&G.interactive_exclude_buf);
	jstr_free_j(&G.interactive_backup_buf);
#endif
}

int
main(int argc, char **argv)
{
	/* FIND/REPLACE are the first two arguments; missing -> print usage. */
	if (jstr_nullchk(argv[1])) {
		fprintf(stderr, "%s", usage);
		return EXIT_FAILURE;
	}
	if (jstr_nullchk(argv[2])) {
		/* Only one extra argument: treat "-h" as help and "--version"/"-v"
		 * as version output; otherwise print the usage as an error. */
		FILE *fp = stderr;
		int ret = EXIT_FAILURE;
		if (!strcmp(argv[1], "-h")) {
			fp = stdout;
			ret = EXIT_SUCCESS;
		}
		if (!strcmp(argv[1], "--version") || !strcmp(argv[1], "-v")) {
			printf("find-and-replace %s\n", VERSION);
			return EXIT_SUCCESS;
		}
		fprintf(fp, "%s", usage);
		return ret;
	}
	struct stat st;
	int ret;
	args_ty a;
	jstr_twoway_ty t;
	a.t = &t;
	const jstr_literal_ty find_init = { (const char *)FIND, (unsigned int)JSTR_DIFF(jstr_unescape_p(FIND), FIND) };
	const jstr_literal_ty rplc_init = { (const char *)RPLC, (unsigned int)JSTR_DIFF(jstr_unescape_p(RPLC), RPLC) };
	memcpy(&a.find, &find_init, sizeof(a.find));
	memcpy(&a.rplc, &rplc_init, sizeof(a.rplc));
	init_defaults();
	/* -c does two full passes: pass 1 (G.confirm_pass=1) only scans and
	 * previews while collecting the file list; pass 2 (after 'y') re-reads
	 * and edits each cached file. */
	G.confirm_pass = 1;
	int end_of_flags = 0;
	unsigned int i;
	/* Process all arguments: flags then files, in order. */
	for (i = 3; ARG; ++i) {
		if (*ARG == '-' && !end_of_flags) {
			/* -i[SUFFIX] */
			if (ARG[1] == 'i') {
				/* Plain -i: rewrite the file in place (no backup). */
				if (ARG[2] == '\0') {
					G.mode = (G.mode & ~MODE_PRINT_STDOUT) | MODE_PRINT_FILE;
				} else {
					/* -iSUFFIX: keep the original as FILE + SUFFIX backup. */
					G.bak_suffix = ARG + S_LEN("-i");
					G.bak_suffix_len = strlen(G.bak_suffix);
					G.mode = (G.mode & ~MODE_PRINT_STDOUT) | MODE_PRINT_FILE_BACKUP;
				}
				continue;
			}
			/* -- flag */
			if (ARG[1] == '-') {
				/* --include */
				if (!strcmp(ARG + 2, "include")) {
					ARG_NEXT();
					if (jstr_nullchk(ARG))
						jstr_errdie("%s: %s", argv[0], "no argument after --include flag.\n");
					G.include_pat = ARG;
					const int re_ret = jstr_re_comp(&G.include_re, ARG, G.cflags);
					if (jstr_unlikely(re_ret != JSTR_RE_RET_NOERROR)) {
						jstr_re_err(re_ret, &G.include_re, "--include pattern \"%s\" is not a valid regex.\n", ARG);
						exit(EXIT_FAILURE);
					}
					G.have_include = 1;
					continue;
				}
				/* --exclude */
				if (!strcmp(ARG + 2, "exclude")) {
					ARG_NEXT();
					if (jstr_nullchk(ARG))
						jstr_errdie("%s: %s", argv[0], "no argument after --exclude flag.\n");
					G.exclude_pat = ARG;
					const int re_ret = jstr_re_comp(&G.exclude_re, ARG, G.cflags);
					if (jstr_unlikely(re_ret != JSTR_RE_RET_NOERROR)) {
						jstr_re_err(re_ret, &G.exclude_re, "--exclude pattern \"%s\" is not a valid regex.\n", ARG);
						exit(EXIT_FAILURE);
					}
					G.have_exclude = 1;
					continue;
				}
				/* bare "--": stop flag parsing */
				if (ARG[2] == '\0') {
					end_of_flags = 1;
					continue;
				}
				/* --version */
				if (!strcmp(ARG + 2, "version")) {
					printf("find-and-replace %s\n", VERSION);
					exit(EXIT_SUCCESS);
				}
				continue;
			}
			/* Single-dash flags, allow combinations */
			{
				const char *argp = ARG + 1;
				for (;; ++argp) {
					switch (*argp) {
					case '\0':
						goto done_single;
					case 'E':
						G.cflags |= JSTR_RE_CF_EXTENDED;
						goto use_regex_flag;
					case 'F':
						G.mode &= ~MODE_USE_REGEX;
						break;
					case 'G':
						G.n = 1;
						break;
					case 'I':
						G.cflags |= JSTR_RE_CF_ICASE;
						goto use_regex_flag;
					case 'R':
						/* -E and -I imply -R: fall through to enable regex mode. */
use_regex_flag:
						G.mode |= MODE_USE_REGEX;
						break;
					case 'Z':
						G.cflags |= JSTR_RE_CF_NEWLINE;
						break;
					case 'c':
						G.mode |= MODE_CONFIRM;
						break;
					case 'g':
						G.n = (size_t)-1;
						break;
					case 'h':
						printf("%s", usage);
						exit(EXIT_SUCCESS);
						break;
					case 'l':
						G.mode |= MODE_PRINT_CHANGES;
						break;
					case 'r':
						G.mode |= MODE_USE_RECURSIVE;
						break;
					case 'z':
						G.cflags &= ~JSTR_RE_CF_NEWLINE;
						break;
					case 'v':
						printf("find-and-replace %s\n", VERSION);
						exit(EXIT_SUCCESS);
						break;
					default:
						fprintf(stderr, "find-and-replace: invalid flag '-%c'. See usage below:\n\n%s", *argp, usage);
						exit(EXIT_FAILURE);
						break;
					}
				}
done_single:;
			}
			continue;
		}
		/* Non-flag argument: a file (or directory with -r) to process. */
		G.mode |= MODE_HAVE_FILES;
		ret = xstat(ARG, &st);
		DIE_IF(ret == JSTR_RET_ERR, "stat(%s) failed.\n", ARG);
		DIE_IF(jstr_chk(compile(&t, &a.find, &a.rplc)), "%s", "");
		if (IS_REG(st.st_mode)) {
			const size_t fname_len = strlen(ARG);
			const jstr_literal_ty fn = { ARG, (unsigned int)fname_len };
			if (!G.have_exclude) {
process:
				DIE_IF(jstr_chk(process_file(&t, &G.content_buf, &fn, &st, &a.find, &a.rplc)), "find-and-replace: error processing '%s' (find=\"%s\", replace=\"%s\").\n", ARG, a.find.data, a.rplc.data);
			} else {
				/* --exclude also filters files named on the command line. */
				const char *fname = jstr_memrchr(ARG, SEP, fname_len);
				fname = (fname != NULL && *(fname + 1)) ? fname + 1 : ARG;
				const size_t base_len = (size_t)(ARG + fname_len - fname);
				if (jstr_re_match_len(&G.exclude_re, fname, base_len, 0) != JSTR_RE_RET_NOERROR)
					goto process;
			}
		} else if (IS_DIR(st.st_mode)) {
			/* Directories are only followed with -r; --include/--exclude are
			 * enforced by the ftw matcher during the traversal. */
			if (G.mode & MODE_USE_RECURSIVE) {
				a.buf = &G.content_buf;
				DIE_IF(jstr_chk(jstr_io_ftw(ARG, callback_file, &a, JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG, (G.have_include || G.have_exclude) ? matcher : NULL, NULL)), "ftw(directory: %s, callback, func_args, flags: JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG, matcher: %s, matcher_args) failed.\n", ARG, G.have_include ? "1" : "0");
			}
		} else {
			fprintf(stderr, "find-and-replace: %s is not a regular file or directory.\n", ARG);
			exit(EXIT_FAILURE);
		}
	}
	/* End of the -c dry-run pass: no file has been touched yet. */
	if (G.confirm_pass && (G.mode & MODE_CONFIRM)) {
		if (jstr_unlikely(!(G.mode & (MODE_PRINT_FILE | MODE_PRINT_FILE_BACKUP))))
			jstr_errdie("%s: -c requires -i.\n", argv[0]);
		if (jstr_unlikely(!(G.mode & MODE_HAVE_FILES)))
			jstr_errdie("%s: -c does not work with stdin.\n", argv[0]);

		jstr_empty_j(&G.interactive_find_buf);
		jstr_empty_j(&G.interactive_rplc_buf);
		jstr_empty_j(&G.interactive_flags_buf);
		jstr_empty_j(&G.interactive_files_buf);
		jstr_empty_j(&G.interactive_include_buf);
		jstr_empty_j(&G.interactive_exclude_buf);
		jstr_empty_j(&G.interactive_backup_buf);

		if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
			DIE_IF(jstr_append_len_j(&G.interactive_find_buf, a.find.data, a.find.size), "%s", "Out of memory.\n");
			DIE_IF(jstr_append_len_j(&G.interactive_rplc_buf, a.rplc.data, a.rplc.size), "%s", "Out of memory.\n");
			if (G.include_pat)
				DIE_IF(jstr_append_len_j(&G.interactive_include_buf, G.include_pat, strlen(G.include_pat)), "%s", "Out of memory.\n");
			if (G.exclude_pat)
				DIE_IF(jstr_append_len_j(&G.interactive_exclude_buf, G.exclude_pat, strlen(G.exclude_pat)), "%s", "Out of memory.\n");
			if (G.bak_suffix)
				DIE_IF(jstr_append_len_j(&G.interactive_backup_buf, G.bak_suffix, G.bak_suffix_len), "%s", "Out of memory.\n");

			char init_flags[16];
			int fl_idx = 0;
			if (G.n == (size_t)-1)
				init_flags[fl_idx++] = 'g';
			else
				init_flags[fl_idx++] = 'G';
			if (G.mode & MODE_USE_REGEX)
				init_flags[fl_idx++] = 'R';
			else
				init_flags[fl_idx++] = 'F';
			if (G.cflags & JSTR_RE_CF_EXTENDED)
				init_flags[fl_idx++] = 'E';
			if (G.cflags & JSTR_RE_CF_ICASE)
				init_flags[fl_idx++] = 'I';
			if (G.cflags & JSTR_RE_CF_NEWLINE)
				init_flags[fl_idx++] = 'Z';
			else
				init_flags[fl_idx++] = 'z';
			if (G.mode & MODE_PRINT_CHANGES)
				init_flags[fl_idx++] = 'l';
			init_flags[fl_idx] = '\0';
			DIE_IF(jstr_append_len_j(&G.interactive_flags_buf, init_flags, fl_idx), "%s", "Out of memory.\n");

			DIE_IF(jstr_chk(confirm_interactive_loop(&t, &G.interactive_find_buf, &G.interactive_rplc_buf, &G.interactive_flags_buf, &G.interactive_files_buf, &G.interactive_include_buf, &G.interactive_exclude_buf, &G.interactive_backup_buf)), "%s", "Interactive loop failed.\n");

			const jstr_literal_ty find_updated = { G.interactive_find_buf.data, (unsigned int)G.interactive_find_buf.size };
			const jstr_literal_ty rplc_updated = { G.interactive_rplc_buf.data, (unsigned int)G.interactive_rplc_buf.size };
			memcpy(&a.find, &find_updated, sizeof(a.find));
			memcpy(&a.rplc, &rplc_updated, sizeof(a.rplc));

			/* Backup suffix edited in the TUI: apply it before the second
			 * pass so process_buffer backs the original up with it. */
			if (G.interactive_backup_buf.size > 0) {
				G.bak_suffix = G.interactive_backup_buf.data;
				G.bak_suffix_len = G.interactive_backup_buf.size;
				G.mode = (G.mode & ~MODE_PRINT_STDOUT) | MODE_PRINT_FILE_BACKUP;
			} else {
				G.bak_suffix = NULL;
				G.bak_suffix_len = 0;
				G.mode = (G.mode & ~MODE_PRINT_STDOUT) | MODE_PRINT_FILE;
			}

			/* Re-print final accepted preview to normal stdout. */
			G.matches_found = 0;
			for (i = 0; i < G.files.size; ++i) {
				file_ty *file = &G.files.data[i];
				if (!file_filter_pass(file, &G.interactive_files_buf))
					continue;
				size_t file_matches = 0;
				const jstr_literal_ty fn = { file->fname, (unsigned int)file->fname_len };
				confirm_scan_file(&t, &file->content, &fn, &a.find, &a.rplc, &file_matches);
			}
		}

		if (G.matches_found) {
			jstr_io_fwrite(CONFIRM_PROMPT, 1, S_LEN(CONFIRM_PROMPT), stdout);
			jstr_io_fflush(stdout);
			/* Only an explicit 'y' proceeds; anything else aborts and leaves
			 * every file untouched. */
			if (jstr_io_getchar() != 'y') {
				jstr_io_fwrite(CONFIRM_ABORTED, 1, S_LEN(CONFIRM_ABORTED), stderr);
				jstr_empty_j(&G.interactive_find_buf);
				jstr_empty_j(&G.interactive_rplc_buf);
				jstr_empty_j(&G.interactive_flags_buf);
				jstr_empty_j(&G.interactive_files_buf);
				jstr_empty_j(&G.interactive_include_buf);
				jstr_empty_j(&G.interactive_exclude_buf);
				jstr_empty_j(&G.interactive_backup_buf);
				exit(EXIT_FAILURE);
			}
			/* Second pass: edit each cached file's content from memory; the
			 * buffers were read once during the scan, so no re-stat or
			 * re-read is needed. The regex/twoway stay compiled. */
			G.confirm_pass = 0;
			G.matches_found = 0;
			struct stat st_file;
			for (i = 0; i < G.files.size; ++i) {
				file_ty *file = &G.files.data[i];
				if (!file_filter_pass(file, &G.interactive_files_buf))
					continue;
				/* Read the file if the content is not in memory. */
				if (jstr_unlikely(file->content.data == NULL)) {
					jstr_empty_j(&G.content_buf);
					DIE_IF(jstr_reserve_j(&G.content_buf, file->content_size), "%s", "Out of memory reading a file.\n");
					DIE_IF(jstr_io_readfile_len_j(&G.content_buf, file->fname, 0, file->content_size), "%s", "Can't read a file->\n");
				}
				st_file.st_mode = file->st_mode;
				const jstr_literal_ty fn = { file->fname, (unsigned int)file->fname_len };
				if (jstr_chk(process_buffer(&t, &file->content, &fn, &st_file, &a.find, &a.rplc)))
					jstr_errdie("find-and-replace: error processing '%s' (find=\"%s\", replace=\"%s\").\n", file->fname, a.find.data, a.rplc.data);
			}
			jstr_empty_j(&G.interactive_find_buf);
			jstr_empty_j(&G.interactive_rplc_buf);
			jstr_empty_j(&G.interactive_flags_buf);
			jstr_empty_j(&G.interactive_files_buf);
			jstr_empty_j(&G.interactive_include_buf);
			jstr_empty_j(&G.interactive_exclude_buf);
			jstr_empty_j(&G.interactive_backup_buf);
		} else {
			jstr_empty_j(&G.interactive_find_buf);
			jstr_empty_j(&G.interactive_rplc_buf);
			jstr_empty_j(&G.interactive_flags_buf);
			jstr_empty_j(&G.interactive_files_buf);
			jstr_empty_j(&G.interactive_include_buf);
			jstr_empty_j(&G.interactive_exclude_buf);
			jstr_empty_j(&G.interactive_backup_buf);
		}
	} else {
		/* If no file was passed, read from stdin. */
		if (!(G.mode & MODE_HAVE_FILES)) {
			/* In-place output and backups are meaningless without a real file. */
			if (jstr_unlikely(G.bak_suffix != NULL) || jstr_unlikely(!(G.mode & MODE_PRINT_STDOUT)))
				jstr_errdie("%s: %s", argv[0], "find-and-replace: trying to create a backup file while reading from stdin.");
			if (jstr_unlikely(G.mode & MODE_USE_RECURSIVE))
				jstr_errdie("%s: %s", argv[0], "trying to recursively traverse through directories while reading from stdin.");
			DIE_IF(jstr_chk(jstr_io_readstdin_j(&G.content_buf)), "%s", "Failed reading stdin.\n");
			DIE_IF(jstr_chk(compile(&t, &a.find, &a.rplc)), "%s", "");
			DIE_IF(jstr_chk(process_buffer(&t, &G.content_buf, NULL, NULL, &a.find, &a.rplc)), "%s", "Failed processing stdin.\n");
		}
	}
	cleanup();
	return EXIT_SUCCESS;
	(void)argc;
}
