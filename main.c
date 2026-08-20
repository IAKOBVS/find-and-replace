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
	_("  -q, --quiet\n")
	_("    Suppress status output: the per-file stderr echo from -i and the\n")
	_("    matching lines in --grep mode (the exit code is still returned).\n")
	_("  --grep\n")
	_("    Print the lines that contain FIND (like grep) and exit 0 if any\n")
	_("    matched, 1 if none, 2 on error. No files are modified. Cannot be\n")
	_("    combined with -i or -c. Matching lines from named files are\n")
	_("    prefixed with FILE:, lines from stdin are printed bare.\n")
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
	_("If no file was passed, read from stdin. A lone - in FILES also reads\n")
	_("stdin at that point in the argument list.\n");

/* clang-format on */

/* Exit code on error: --grep follows grep's convention of 2 for errors
 * (distinct from 1 = no match); every other mode keeps EXIT_FAILURE. */
static int
err_exit_code()
{
	return (G.mode & MODE_GREP) ? 2 : EXIT_FAILURE;
}

/* Compile FIND (regex or Two-Way fixed-string matcher) into the global
 * state. Recompiles when the regex mode/cflags change between files; the
 * MODE_COMPILED bit alone cannot guard that, since -R/-E/-F may appear
 * anywhere on the command line, even after a file argument. */
static jstr_ret_ty
compile(jstr_twoway_ty *R t, const char *R find, size_t find_len, const char *R rplc, size_t rplc_len)
{
	const int want_regex = (G.mode & MODE_USE_REGEX) != 0;
	if (!(G.mode & MODE_COMPILED) || want_regex != G.compiled_regex || (want_regex && G.cflags != G.compiled_cflags)) {
		if (G.mode & MODE_COMPILED) {
			if (G.compiled_regex)
				jstr_re_free(&G.regex);
			G.mode &= ~MODE_COMPILED;
		}
		if (want_regex) {
			const int ret = jstr_re_comp(&G.regex, find, G.cflags);
			if (jstr_unlikely(ret != JSTR_RE_RET_NOERROR)) {
				jstr_re_err(ret, &G.regex, "regex compilation failed for pattern \"%s\".\n", find);
				exit(err_exit_code());
			}
			/* Validate backreferences */
			size_t max_backref = 0;
			for (size_t idx = 0; idx + 1 < rplc_len; ++idx) {
				if (rplc[idx] == '\\' && rplc[idx+1] >= '1' && rplc[idx+1] <= '9') {
					size_t num = rplc[idx+1] - '0';
					if (num > max_backref)
						max_backref = num;
					++idx;
				}
			}
			if (jstr_unlikely(max_backref > G.regex.reg.re_nsub)) {
				fprintf(stderr, "find-and-replace error: Replace backreference \\%zu exceeds find capture groups (%zu)\n", max_backref, G.regex.reg.re_nsub);
				exit(err_exit_code());
			}
		} else {
			jstr_memmem_comp(t, find, find_len);
		}
		G.compiled_regex = want_regex;
		G.compiled_cflags = G.cflags;
		G.mode |= MODE_COMPILED;
	}
	return JSTR_RET_SUCC;
}

/* Default flags. Idempotent: assigns (never ORs) so calling it again cannot
 * leak state from an earlier call. */
static void
init_defaults()
{
	/* Anchors match on newlines. */
	G.cflags = JSTR_RE_CF_NEWLINE;
	/* Non-global replacement. */
	G.n = 1;
	G.eflags = 0;
}

/* Return 1 if FILE passes the -c confirm filters: the interactive Files
 * substring filter, the --include regex and the --exclude regex (both
 * compiled into the global state by the flag parser or the confirm TUI). */
static int
file_filter_pass(const file_ty *R file, const jstr_ty *R files_buf)
{
	if (files_buf->size > 0 && files_buf->data)
		if (jstr_strstr_len(file->fname, file->fname_len, files_buf->data, files_buf->size) == NULL)
			return 0;
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

/* Handle single-character combined flags (e.g., -EI, -gR). */
static void
parse_single_flags(const char *arg)
{
	for (const char *argp = arg + 1; *argp != '\0'; ++argp) {
		switch (*argp) {
		case 'E':
			G.cflags |= JSTR_RE_CF_EXTENDED;
			G.mode |= MODE_USE_REGEX;
			break;
		case 'F':
			G.mode &= ~MODE_USE_REGEX;
			break;
		case 'G':
			G.n = 1;
			break;
		case 'I':
			G.cflags |= JSTR_RE_CF_ICASE;
			G.mode |= MODE_USE_REGEX;
			break;
		case 'R':
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
		case 'l':
			G.mode |= MODE_PRINT_CHANGES;
			break;
		case 'q':
			G.mode |= MODE_QUIET;
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
		default:
			fprintf(stderr, "find-and-replace: invalid flag '-%c'. See usage below:\n\n%s", *argp, usage);
			exit(err_exit_code());
		}
	}
}

/* Handle double-dash flags (e.g. --include, --exclude, --grep). */
static int
parse_long_flag(char **argv, unsigned int *i_ptr, int *end_of_flags)
{
	const char *arg = argv[*i_ptr];
	if (!strcmp(arg + 2, "include")) {
		(*i_ptr)++;
		if (jstr_nullchk(argv[*i_ptr]))
			jstr_errdie("%s: %s", argv[0], "no argument after --include flag.\n");
		G.include_pat = argv[*i_ptr];
		const int re_ret = jstr_re_comp(&G.include_re, argv[*i_ptr], G.cflags);
		if (jstr_unlikely(re_ret != JSTR_RE_RET_NOERROR)) {
			jstr_re_err(re_ret, &G.include_re, "--include pattern \"%s\" is not a valid regex.\n", argv[*i_ptr]);
			exit(err_exit_code());
		}
		G.have_include = 1;
		return 1;
	}
	if (!strcmp(arg + 2, "exclude")) {
		(*i_ptr)++;
		if (jstr_nullchk(argv[*i_ptr]))
			jstr_errdie("%s: %s", argv[0], "no argument after --exclude flag.\n");
		G.exclude_pat = argv[*i_ptr];
		const int re_ret = jstr_re_comp(&G.exclude_re, argv[*i_ptr], G.cflags);
		if (jstr_unlikely(re_ret != JSTR_RE_RET_NOERROR)) {
			jstr_re_err(re_ret, &G.exclude_re, "--exclude pattern \"%s\" is not a valid regex.\n", argv[*i_ptr]);
			exit(err_exit_code());
		}
		G.have_exclude = 1;
		return 1;
	}
	if (arg[2] == '\0') {
		*end_of_flags = 1;
		return 1;
	}
	if (!strcmp(arg + 2, "grep")) {
		G.mode |= MODE_GREP;
		if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO))
			G.grep_collect = 1;
		return 1;
	}
	if (!strcmp(arg + 2, "quiet")) {
		G.mode |= MODE_QUIET;
		return 1;
	}
	if (!strcmp(arg + 2, "version")) {
		printf("find-and-replace %s\n", VERSION);
		exit(EXIT_SUCCESS);
	}
	return 1;
}

/* Process a lone "-" stdin placeholder. */
static jstr_ret_ty
process_stdin_arg(const args_ty *a, jstr_twoway_ty *t, const char *prog_name)
{
	if (G.mode & MODE_CONFIRM)
		jstr_errdie("%s: -c does not work with '-' (stdin).\n", prog_name);
	if (G.mode & (MODE_PRINT_FILE | MODE_PRINT_FILE_BACKUP))
		jstr_errdie("%s: -i is meaningless with '-' (stdin).\n", prog_name);
	if (G.mode & MODE_USE_RECURSIVE)
		jstr_errdie("%s: -r is meaningless with '-' (stdin).\n", prog_name);
	if (a->find_len == 0) {
		if (!(G.mode & MODE_GREP)) {
			DIE_IF(jstr_chk(jstr_io_readstdin_j(&G.content_buf)), "%s", "Failed reading stdin.\n");
			if (jstr_unlikely(jstr_io_fwrite(G.content_buf.data, 1, G.content_buf.size, stdout) != G.content_buf.size))
				return JSTR_RET_ERR;
		}
		return JSTR_RET_SUCC;
	}
	DIE_IF(jstr_chk(jstr_io_readstdin_j(&G.content_buf)), "%s", "Failed reading stdin.\n");
	DIE_IF(jstr_chk(compile(t, a->find, a->find_len, a->rplc, a->rplc_len)), "%s", "");
	if (G.mode & MODE_GREP)
		DIE_IF(jstr_chk(grep_scan_file(t, &G.content_buf, NULL, 0, a->find, a->find_len)), "%s", "Failed grep on stdin.\n");
	else
		DIE_IF(jstr_chk(process_buffer(t, &G.content_buf, NULL, 0, NULL, a->find, a->find_len, a->rplc, a->rplc_len)), "%s", "Failed processing stdin.\n");
	return JSTR_RET_SUCC;
}

/* Process a target regular file or directory argument. */
static void
process_target_arg(const char *arg, args_ty *a, jstr_twoway_ty *t)
{
	struct stat st;
	int ret = xstat(arg, &st);
	if (jstr_unlikely(ret == JSTR_RET_ERR)) {
		fprintf(stderr, "find-and-replace: stat(%s) failed.\n", arg);
		exit(err_exit_code());
	}
	DIE_IF(jstr_chk(compile(t, a->find, a->find_len, a->rplc, a->rplc_len)), "%s", "");
	if (IS_REG(st.st_mode)) {
		const size_t fname_len = strlen(arg);
		if (!G.have_exclude) {
process_file_label:
			if (jstr_chk(process_file(t, &G.content_buf, arg, fname_len, &st, a->find, a->find_len, a->rplc, a->rplc_len))) {
				fprintf(stderr, "find-and-replace: error processing '%s' (find=\"%s\", replace=\"%s\").\n", arg, a->find, a->rplc);
				exit(err_exit_code());
			}
		} else {
			const char *fname = jstr_memrchr(arg, SEP, fname_len);
			fname = (fname != NULL && *(fname + 1)) ? fname + 1 : arg;
			const size_t base_len = (size_t)(arg + fname_len - fname);
			if (jstr_re_match_len(&G.exclude_re, fname, base_len, 0) != JSTR_RE_RET_NOERROR)
				goto process_file_label;
		}
	} else if (IS_DIR(st.st_mode)) {
		if (G.mode & MODE_USE_RECURSIVE) {
			a->buf = &G.content_buf;
			if (jstr_chk(jstr_io_ftw(arg, callback_file, a, JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG, (G.have_include || G.have_exclude) ? matcher : NULL, NULL))) {
				fprintf(stderr, "ftw(directory: %s, callback, func_args, flags: JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG, matcher: %s, matcher_args) failed.\n", arg, G.have_include ? "1" : "0");
				exit(err_exit_code());
			}
		}
	} else {
		fprintf(stderr, "find-and-replace: %s is not a regular file or directory.\n", arg);
		exit(err_exit_code());
	}
}

/* Handle confirm mode passes (TUI editing, confirmation prompt, and second-pass writing). */
static void
run_confirm_mode(args_ty *a, jstr_twoway_ty *t, const char *raw_find, const char *raw_rplc, char **argv)
{
	unsigned int i;
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
		DIE_IF(jstr_chk(jstr_append_len_j(&G.interactive_find_buf, raw_find, strlen(raw_find))), "%s", "Out of memory.\n");
		DIE_IF(jstr_append_len_j(&G.interactive_rplc_buf, raw_rplc, strlen(raw_rplc)), "%s", "Out of memory.\n");
		if (G.include_pat)
			DIE_IF(jstr_chk(jstr_append_len_j(&G.interactive_include_buf, G.include_pat, strlen(G.include_pat))), "%s", "Out of memory.\n");
		if (G.exclude_pat)
			DIE_IF(jstr_chk(jstr_append_len_j(&G.interactive_exclude_buf, G.exclude_pat, strlen(G.exclude_pat))), "%s", "Out of memory.\n");
		if (G.bak_suffix)
			DIE_IF(jstr_chk(jstr_append_len_j(&G.interactive_backup_buf, G.bak_suffix, G.bak_suffix_len)), "%s", "Out of memory.\n");

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
		DIE_IF(jstr_chk(jstr_append_len_j(&G.interactive_flags_buf, init_flags, (unsigned int)fl_idx)), "%s", "Out of memory.\n");

		DIE_IF(jstr_chk(confirm_interactive_loop(t, &G.interactive_find_buf, &G.interactive_rplc_buf, &G.interactive_flags_buf, &G.interactive_files_buf, &G.interactive_include_buf, &G.interactive_exclude_buf, &G.interactive_backup_buf)), "%s", "Interactive loop failed.\n");

		a->find = G.interactive_find_buf.data;
		a->find_len = JSTR_DIFF(jstr_unescape_p(G.interactive_find_buf.data), G.interactive_find_buf.data);
		G.interactive_find_buf.size = a->find_len;
		a->rplc = G.interactive_rplc_buf.data;
		a->rplc_len = JSTR_DIFF(jstr_unescape_p(G.interactive_rplc_buf.data), G.interactive_rplc_buf.data);
		G.interactive_rplc_buf.size = a->rplc_len;

		if (G.interactive_backup_buf.size > 0) {
			G.bak_suffix = G.interactive_backup_buf.data;
			G.bak_suffix_len = G.interactive_backup_buf.size;
			G.mode = (G.mode & ~MODE_PRINT_STDOUT) | MODE_PRINT_FILE_BACKUP;
		} else {
			G.bak_suffix = NULL;
			G.bak_suffix_len = 0;
			G.mode = (G.mode & ~MODE_PRINT_STDOUT) | MODE_PRINT_FILE;
		}

		G.matches_found = 0;
		G.preview_full = 0;
		for (i = 0; i < G.files.size; ++i) {
			file_ty *file = &G.files.data[i];
			if (!file_filter_pass(file, &G.interactive_files_buf))
				continue;
			size_t file_matches = 0;
			confirm_scan_file(t, &file->content, file->fname, file->fname_len, a->find, a->find_len, a->rplc, a->rplc_len, &file_matches);
			if (G.preview_full)
				break;
		}
		if (G.preview_full)
			(void)jstr_unlikely(jstr_io_fwrite("... (some previews omitted)\n", 1, S_LEN("... (some previews omitted)\n"), stdout) != S_LEN("... (some previews omitted)\n"));
	}

	if (G.matches_found) {
		if (jstr_unlikely(jstr_io_fwrite(CONFIRM_PROMPT, 1, S_LEN(CONFIRM_PROMPT), stdout) != S_LEN(CONFIRM_PROMPT))) {
			fprintf(stderr, "find-and-replace: write error on prompt.\n");
			cleanup();
			exit(EXIT_FAILURE);
		}
		if (jstr_unlikely(jstr_io_fflush(stdout) == EOF)) {
			fprintf(stderr, "find-and-replace: flush error on prompt.\n");
			cleanup();
			exit(EXIT_FAILURE);
		}
		if (jstr_io_getchar() != 'y') {
			(void)jstr_unlikely(jstr_io_fwrite(CONFIRM_ABORTED, 1, S_LEN(CONFIRM_ABORTED), stderr) != S_LEN(CONFIRM_ABORTED));
			cleanup();
			exit(EXIT_FAILURE);
		}
		G.confirm_pass = 0;
		G.matches_found = 0;
		struct stat st_file;
		for (i = 0; i < G.files.size; ++i) {
			file_ty *file = &G.files.data[i];
			if (!file_filter_pass(file, &G.interactive_files_buf))
				continue;
			jstr_ty *const rbuf = (file->content.data == NULL) ? &G.content_buf : &file->content;
			if (jstr_unlikely(file->content.data == NULL)) {
				jstr_empty_j(&G.content_buf);
				DIE_IF(jstr_chk(jstr_reserve_j(&G.content_buf, file->content_size)), "%s", "Out of memory reading a file.\n");
				DIE_IF(jstr_chk(jstr_io_readfile_len_j(&G.content_buf, file->fname, 0, file->content_size)), "%s", "Can't read a file->\n");
			}
			st_file.st_mode = file->st_mode;
			if (jstr_chk(process_buffer(t, rbuf, file->fname, file->fname_len, &st_file, a->find, a->find_len, a->rplc, a->rplc_len)))
				jstr_errdie("find-and-replace: error processing '%s' (find=\"%s\", replace=\"%s\").\n", file->fname, a->find, a->rplc);
		}
	}
}

/* Process stdin fallback when no file argument was passed. */
static jstr_ret_ty
process_no_files_stdin(args_ty *a, jstr_twoway_ty *t, char **argv)
{
	if (jstr_unlikely(G.bak_suffix != NULL) || jstr_unlikely(!(G.mode & MODE_PRINT_STDOUT)))
		jstr_errdie("%s: %s", argv[0], "find-and-replace: trying to create a backup file while reading from stdin.");
	if (jstr_unlikely(G.mode & MODE_USE_RECURSIVE))
		jstr_errdie("%s: %s", argv[0], "trying to recursively traverse through directories while reading from stdin.");
	if (a->find_len == 0) {
		if (!(G.mode & MODE_GREP)) {
			DIE_IF(jstr_chk(jstr_io_readstdin_j(&G.content_buf)), "%s", "Failed reading stdin.\n");
			if (jstr_unlikely(jstr_io_fwrite(G.content_buf.data, 1, G.content_buf.size, stdout) != G.content_buf.size))
				return JSTR_RET_ERR;
		} else {
			G.grep_matched = 1;
		}
	} else {
		DIE_IF(jstr_chk(jstr_io_readstdin_j(&G.content_buf)), "%s", "Failed reading stdin.\n");
		DIE_IF(jstr_chk(compile(t, a->find, a->find_len, a->rplc, a->rplc_len)), "%s", "");
		if (G.mode & MODE_GREP)
			DIE_IF(jstr_chk(grep_scan_file(t, &G.content_buf, NULL, 0, a->find, a->find_len)), "%s", "Failed grep on stdin.\n");
		else
			DIE_IF(jstr_chk(process_buffer(t, &G.content_buf, NULL, 0, NULL, a->find, a->find_len, a->rplc, a->rplc_len)), "%s", "Failed processing stdin.\n");
	}
	return JSTR_RET_SUCC;
}

int
main(int argc, char **argv)
{
	/* Give stdout a large buffer to batch the many small fwrite/putc calls
	 * during TUI redraws; fflush is called explicitly at each frame end. */
	setvbuf(stdout, NULL, _IOFBF, 16384);
	/* FIND/REPLACE are the first two arguments; missing -> print usage. */
	if (jstr_nullchk(argv[1])) {
		fprintf(stderr, "%s", usage);
		return EXIT_FAILURE;
	}
	if (jstr_nullchk(argv[2])) {
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
	args_ty a = { 0 };
	jstr_twoway_ty t;
	a.t = &t;
	a.find = (const char *)FIND;
	const char *raw_find = (const char *)FIND;
	a.find_len = JSTR_DIFF(jstr_unescape_p(FIND), FIND);
	const char *raw_rplc;
	a.rplc = (const char *)RPLC;
	raw_rplc = (const char *)RPLC;
	a.rplc_len = JSTR_DIFF(jstr_unescape_p(RPLC), RPLC);
	unsigned int i = 3;
	init_defaults();
	G.confirm_pass = 1;
	int end_of_flags = 0;
	for (; ARG; ++i) {
		if (*ARG == '-' && ARG[1] != '\0' && !end_of_flags) {
			if (ARG[1] == 'i') {
				if (ARG[2] == '\0') {
					G.mode = (G.mode & ~MODE_PRINT_STDOUT) | MODE_PRINT_FILE;
				} else {
					G.bak_suffix = ARG + S_LEN("-i");
					G.bak_suffix_len = strlen(G.bak_suffix);
					G.mode = (G.mode & ~MODE_PRINT_STDOUT) | MODE_PRINT_FILE_BACKUP;
				}
				continue;
			}
			if (ARG[1] == '-') {
				if (parse_long_flag(argv, &i, &end_of_flags))
					continue;
			}
			parse_single_flags(ARG);
			continue;
		}
		G.mode |= MODE_HAVE_FILES;
		if (a.find_len == 0) {
			if (G.mode & MODE_GREP)
				G.grep_matched = 1;
			if (!(G.mode & (MODE_CONFIRM | MODE_GREP)))
				continue;
		}
		if (ARG[0] == '-' && ARG[1] == '\0') {
			if (jstr_chk(process_stdin_arg(&a, &t, argv[0]))) {
				cleanup();
				exit(err_exit_code());
			}
			continue;
		}
		process_target_arg(ARG, &a, &t);
	}
	if (jstr_unlikely((G.mode & MODE_GREP) && (G.mode & (MODE_CONFIRM | MODE_PRINT_FILE | MODE_PRINT_FILE_BACKUP)))) {
		fprintf(stderr, "find-and-replace error: --grep cannot be combined with -i or -c.\n");
		exit(err_exit_code());
	}
	if (G.confirm_pass && (G.mode & MODE_CONFIRM)) {
		run_confirm_mode(&a, &t, raw_find, raw_rplc, argv);
	} else {
		if (!(G.mode & MODE_HAVE_FILES)) {
			if (jstr_chk(process_no_files_stdin(&a, &t, argv))) {
				cleanup();
				exit(err_exit_code());
			}
		}
	}
	if (jstr_unlikely(a.err_count > 0)) {
		fprintf(stderr, "find-and-replace: %zu file(s) failed during processing.\n", a.err_count);
		cleanup();
		return err_exit_code();
	}
	if (G.mode & MODE_GREP) {
		if (G.grep_collect && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
			jstr_empty_j(&G.interactive_find_buf);
			jstr_empty_j(&G.interactive_files_buf);
			jstr_empty_j(&G.interactive_include_buf);
			jstr_empty_j(&G.interactive_exclude_buf);
			DIE_IF(jstr_chk(jstr_append_len_j(&G.interactive_find_buf, raw_find, strlen(raw_find))), "%s", "Out of memory.\n");
			if (G.include_pat)
				DIE_IF(jstr_chk(jstr_append_len_j(&G.interactive_include_buf, G.include_pat, strlen(G.include_pat))), "%s", "Out of memory.\n");
			if (G.exclude_pat)
				DIE_IF(jstr_chk(jstr_append_len_j(&G.interactive_exclude_buf, G.exclude_pat, strlen(G.exclude_pat))), "%s", "Out of memory.\n");
			grep_interactive_loop(&t, &G.interactive_find_buf, &G.interactive_files_buf, &G.interactive_include_buf, &G.interactive_exclude_buf);
		}
		cleanup();
		return G.grep_matched ? EXIT_SUCCESS : EXIT_FAILURE;
	}
	cleanup();
	return EXIT_SUCCESS;
	(void)argc;
}
