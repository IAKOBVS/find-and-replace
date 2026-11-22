/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "stage.h"
#include "io.h"
#include "traverse.h"
#include "process.h"
#include "terminal.h"
#include "ui.h"
#include "pipeline.h"

#include <errno.h>
#include <stdint.h>

#define IS_REG(x) S_ISREG(x)
#define IS_DIR(x) S_ISDIR(x)
#define ARG                 argv[i]
#define ARG_NEXT()          ++i
#define ARG_PREV()          --i
#define FIND                argv[1]
#define RPLC                argv[2]
#define SEP                 '/'

#define VERSION             "0.1.0"

typedef enum {
	PARSE_FLAGS,
	PARSE_FILES
} parser_state_ty;

#define _(x) x

global_ty G = { .output_mode = OUT_STDOUT };

/* clang-format off */

static const char *usage =
	_("Usage: find-and-replace [FIND] [REPLACE] [OPTIONS]. [FILES].\n")
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
	_("  -j N\n")
	_("    Use N file-processing worker threads (default: nproc).\n")
	_("  -q, --quiet\n")
	_("    Suppress status output: the per-file stderr echo from -i and the\n")
	_("    matching lines in --grep mode (the exit code is still returned).\n")
	_("  --grep\n")
	_("    Print the lines that contain FIND (like grep) and exit 0 if any\n")
	_("    matched, 1 if none, 2 on error. No files are modified. Cannot be\n")
	_("    combined with -i or -c. Matching lines from named files are\n")
	_("    prefixed with FILE:, lines from stdin are printed bare.\n")
	_("    On a terminal, --grep opens a match browser: ESC-j/ESC-k select a\n")
	_("    match line, Enter prints that FILE:LINE:content to stdout and exits.\n")
	_("    Up/Down and Ctrl-J/K change the active field.\n")
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
/**
 * @anchor spec_err_exit_code
 * @brief Return the mode-specific error exit code.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static int
err_exit_code()
{
	return (G.mode & MODE_GREP) ? 2 : EXIT_FAILURE;
}

/**
 * @anchor spec_check_grep_conflicts
 * @brief Reject flag combinations that are invalid in grep mode.
 *
 * @details Called at each flag parse site so an invalid combination fails
 *          before any target is processed or an interactive TUI is opened.
 * @pre G reflects all flags parsed so far.
 * @return None; exits with the grep-specific error code on conflict.
 * @par Side Effects:
 *   Writes a diagnostic to stderr and exits on conflict.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static void
check_grep_conflicts(void)
{
	if (jstr_unlikely((G.mode & MODE_GREP) && ((G.mode & MODE_CONFIRM) || G.output_mode != OUT_STDOUT))) {
		fprintf(stderr, "find-and-replace error: --grep cannot be combined with -i or -c.\n");
		exit(err_exit_code());
	}
}

/* Default flags. Idempotent: assigns (never ORs) so calling it again cannot
 * leak state from an earlier call. */
/**
 * @anchor spec_init_defaults
 * @brief Initialize global defaults idempotently.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
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
/**
 * @anchor spec_file_filter_pass
 * @brief Apply the interactive Files substring filter to a cached file.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param file parameter defined by the owning module contract.
 * @param files_buf Files substring buffer.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
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

/**
 * @anchor spec_cleanup
 * @brief Free or intentionally retain reusable global buffers before exit.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static void
cleanup()
{
	pipeline_shutdown();
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
	jstr_free_j(&G.interactive_find_buf);
	jstr_free_j(&G.interactive_rplc_buf);
	jstr_free_j(&G.interactive_flags_buf);
	jstr_free_j(&G.interactive_files_buf);
	jstr_free_j(&G.interactive_include_buf);
	jstr_free_j(&G.interactive_exclude_buf);
	jstr_free_j(&G.interactive_backup_buf);
	jstr_free_j(&G.find_plain);
	jstr_free_j(&G.rplc_plain);
	free(G.new_ranges.data);
	free(G.old_ranges.data);
#endif
}

/* Handle single-character combined flags (e.g., -EI, -gR). */
/**
 * @anchor spec_parse_single_flags
 * @brief Parse one combined short-flag argument.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param arg parameter defined by the owning module contract.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
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
			check_grep_conflicts();
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
/**
 * @anchor spec_parse_long_flag
 * @brief Parse one long flag and its optional value.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param argv argument vector.
 * @param i_ptr parameter defined by the owning module contract.
 * @param state parser state, changes to PARSE_FILES after --.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static int
parse_long_flag(char **argv, unsigned int *i_ptr, parser_state_ty *state)
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
		*state = PARSE_FILES;
		return 1;
	}
	if (!strcmp(arg + 2, "grep")) {
		G.mode |= MODE_GREP;
		check_grep_conflicts();
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

/**
 * @anchor spec_compile_or_die
 * @brief Compile the matcher or exit with the mode-specific code.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param t compiled fixed-string matcher.
 * @param find find string.
 * @param find_len FIND byte length.
 * @param rplc replacement string.
 * @param rplc_len REPLACE byte length.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static void
compile_or_die(jstr_twoway_ty *t, const char *find, size_t find_len, const char *rplc, size_t rplc_len)
{
	char err_buf[256];
	if (far_compile(t, find, find_len, rplc, rplc_len, 0, err_buf, sizeof(err_buf)) != JSTR_RET_SUCC) {
		fprintf(stderr, "find-and-replace error: %s\n", err_buf);
		exit(err_exit_code());
	}
}

/* Process the stdin target (a single '-' placeholder or missing target). */
/**
 * @anchor spec_process_stdin_arg
 * @brief Run stdin as a target root using CLI rules.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param a parsed CLI arguments.
 * @param t compiled fixed-string matcher.
 * @param prog_name program name used in diagnostics.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static jstr_ret_ty
process_stdin_arg(args_ty *a, jstr_twoway_ty *t, const char *prog_name)
{
	if (G.mode & MODE_CONFIRM)
		jstr_errdie("%s: -c does not work with '-' (stdin).\n", prog_name);
	if (G.output_mode != OUT_STDOUT)
		jstr_errdie("%s: -i is meaningless with '-' (stdin).\n", prog_name);
	if (G.mode & MODE_USE_RECURSIVE)
		jstr_errdie("%s: -r is meaningless with '-' (stdin).\n", prog_name);
	if (a->find_len == 0)
		return JSTR_RET_SUCC;
	compile_or_die(t, a->find, a->find_len, a->rplc, a->rplc_len);
	a->confirm_phase = CONFIRM_NONE;
	root_ctx_ty root;
	root.kind = FAR_ROOT_STDIN;
	root.path = NULL;
	memset(&root.st, 0, sizeof root.st);
	root.mem_files = NULL;
	root.mem_count = 0;
	root.a = a;
	root.t = t;
	const size_t before = a->err_count;
	if (jstr_chk(pipeline_run(&root)) || a->err_count > before) {
		if (G.mode & MODE_GREP)
			fprintf(stderr, "%s", "Failed grep on stdin.\n");
		else
			fprintf(stderr, "%s", "Failed processing stdin.\n");
		exit(err_exit_code());
	}
	return JSTR_RET_SUCC;
}

typedef struct file_batch_ty {
	far_path_stat_ty *data;
	size_t size;
	size_t cap;
} file_batch_ty;

/**
 * @anchor spec_parse_workers_value
 * @brief Parse and validate a -j worker count value.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param prog program name used in diagnostics.
 * @param s input string.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static size_t
parse_workers_value(const char *prog, const char *s)
{
	if (s == NULL || *s == '\0' || *s == '-') {
		fprintf(stderr, "%s: invalid worker count '%s'.\n", prog, s != NULL ? s : "");
		exit(EXIT_FAILURE);
	}
	errno = 0;
	char *end;
	const unsigned long v = strtoul(s, &end, 10);
	if (errno != 0 || *end != '\0' || v == 0) {
		fprintf(stderr, "%s: invalid worker count '%s'.\n", prog, s != NULL ? s : "");
		exit(EXIT_FAILURE);
	}
	return (size_t)v;
}

/**
 * @anchor spec_preparse_workers
 * @brief Scan argv for -j before pipeline startup.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param argc argument count.
 * @param argv argument vector.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static void
preparse_workers(int argc, char **argv)
{
	for (int k = 3; k < argc; ++k) {
		const char *const arg = argv[k];
		if (!strcmp(arg, "--"))
			break;
		if (!strcmp(arg, "--include") || !strcmp(arg, "--exclude")) {
			++k;
			continue;
		}
		if (!strcmp(arg, "-j")) {
			if (k + 1 >= argc) {
				fprintf(stderr, "%s: no argument after -j flag.\n", argv[0]);
				exit(EXIT_FAILURE);
			}
			pipeline_set_workers(parse_workers_value(argv[0], argv[++k]));
		} else if (!strncmp(arg, "-j", 2) && arg[2] != '\0') {
			pipeline_set_workers(parse_workers_value(argv[0], arg + 2));
		}
	}
}

/**
 * @anchor spec_batch_add
 * @brief Append a regular-file target to the pending batch.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param batch pending explicit-file target batch.
 * @param path target path.
 * @param st file status.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static void
batch_add(file_batch_ty *R batch, const char *path, const struct stat *st)
{
	if (batch->size >= batch->cap) {
		const size_t cap = batch->cap == 0 ? 16 : batch->cap * 2;
		far_path_stat_ty *const tmp = (far_path_stat_ty *)realloc(batch->data, cap * sizeof *tmp);
		if (jstr_unlikely(!tmp))
			jstr_errdie("%s", "Out of memory.\n");
		batch->data = tmp;
		batch->cap = cap;
	}
	batch->data[batch->size].path = path;
	batch->data[batch->size].st = *st;
	++batch->size;
}

/**
 * @anchor spec_flush_file_batch
 * @brief Run one FAR_ROOT_FILES root and clear the batch.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param a parsed CLI arguments.
 * @param t compiled fixed-string matcher.
 * @param batch pending explicit-file target batch.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static void
flush_file_batch(args_ty *a, jstr_twoway_ty *t, file_batch_ty *R batch)
{
	if (batch->size == 0)
		return;
	compile_or_die(t, a->find, a->find_len, a->rplc, a->rplc_len);
	a->confirm_phase = (G.mode & MODE_CONFIRM) ? CONFIRM_SCAN : CONFIRM_NONE;
	root_ctx_ty root;
	root.kind = FAR_ROOT_FILES;
	root.path = NULL;
	memset(&root.st, 0, sizeof root.st);
	root.mem_files = NULL;
	root.mem_count = 0;
	root.file_args = batch->data;
	root.file_arg_count = batch->size;
	root.a = a;
	root.t = t;
	const size_t before = a->err_count;
	const jstr_ret_ty ret = pipeline_run(&root);
	if (jstr_chk(ret) || a->err_count > before) {
		if (batch->size == 1)
			fprintf(stderr, "find-and-replace: error processing '%s' (find=\"%s\", replace=\"%s\").\n", batch->data[0].path, a->find, a->rplc);
		else
			fprintf(stderr, "find-and-replace: error processing %zu files (find=\"%s\", replace=\"%s\").\n", batch->size, a->find, a->rplc);
		exit(err_exit_code());
	}
	batch->size = 0;
}

/* Process a target regular file or directory argument. */
/**
 * @anchor spec_process_target_arg
 * @brief Classify one CLI target and dispatch it.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param arg parameter defined by the owning module contract.
 * @param a parsed CLI arguments.
 * @param t compiled fixed-string matcher.
 * @param batch pending explicit-file target batch.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static void
process_target_arg(const char *arg, args_ty *a, jstr_twoway_ty *t, file_batch_ty *batch)
{
	struct stat st;
	int ret = xstat(arg, &st);
	if (jstr_unlikely(ret == JSTR_RET_ERR)) {
		flush_file_batch(a, t, batch);
		fprintf(stderr, "find-and-replace: stat(%s) failed.\n", arg);
		exit(err_exit_code());
	}
	if (IS_REG(st.st_mode)) {
		const size_t fname_len = strlen(arg);
		if (G.have_exclude) {
			const char *fname = jstr_memrchr(arg, SEP, fname_len);
			fname = (fname != NULL && *(fname + 1)) ? fname + 1 : arg;
			const size_t base_len = (size_t)(arg + fname_len - fname);
			if (jstr_re_match_len(&G.exclude_re, fname, base_len, 0) == JSTR_RE_RET_NOERROR)
				return;
		}
		batch_add(batch, arg, &st);
	} else if (IS_DIR(st.st_mode)) {
		flush_file_batch(a, t, batch);
		compile_or_die(t, a->find, a->find_len, a->rplc, a->rplc_len);
		if (G.mode & MODE_USE_RECURSIVE) {
			a->confirm_phase = (G.mode & MODE_CONFIRM) ? CONFIRM_SCAN : CONFIRM_NONE;
			root_ctx_ty root;
			root.kind = FAR_ROOT_DIR;
			root.path = arg;
			memset(&root.st, 0, sizeof root.st);
			root.mem_files = NULL;
			root.mem_count = 0;
			root.a = a;
			root.t = t;
			if (jstr_chk(pipeline_run(&root))) {
				fprintf(stderr, "ftw(directory: %s, callback, func_args, flags: JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG, matcher: %s, matcher_args) failed.\n", arg, G.have_include ? "1" : "0");
				exit(err_exit_code());
			}
		}
	} else {
		flush_file_batch(a, t, batch);
		fprintf(stderr, "find-and-replace: %s is not a regular file or directory.\n", arg);
		exit(err_exit_code());
	}
}

/* Handle confirm mode passes (TUI editing, confirmation prompt, and second-pass writing). */
/**
 * @anchor spec_run_confirm_mode
 * @brief Drive confirm pass 1, TUI, prompt, and pass 2.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param a parsed CLI arguments.
 * @param t compiled fixed-string matcher.
 * @param raw_find unescaped FIND before interactive editing.
 * @param raw_rplc unescaped REPLACE before interactive editing.
 * @param argv argument vector.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static void
run_confirm_mode(args_ty *a, jstr_twoway_ty *t, const char *raw_find, const char *raw_rplc, char **argv)
{
	unsigned int i;
	if (jstr_unlikely(G.output_mode == OUT_STDOUT))
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
			G.output_mode = OUT_BACKUP;
		} else {
			G.bak_suffix = NULL;
			G.bak_suffix_len = 0;
			G.output_mode = OUT_INPLACE;
		}

		G.matches_found = 0;
		G.preview_full = 0;
		for (i = 0; i < G.files.size; ++i) {
			file_ty *file = &G.files.data[i];
			if (!file_filter_pass(file, &G.interactive_files_buf))
				continue;
			size_t file_matches = 0;
			ui_scan_file(t, &file->content, file->fname, file->fname_len, a->find, a->find_len, a->rplc, a->rplc_len, &file_matches);
			if (G.preview_full)
				break;
		}
		if (G.preview_full)
			(void)jstr_unlikely(jstr_io_fwrite(". (some previews omitted)\n", 1, S_LEN(". (some previews omitted)\n"), stdout) != S_LEN(". (some previews omitted)\n"));
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
		a->confirm_phase = CONFIRM_WRITE;
		G.matches_found = 0;
		const file_ty **list = (const file_ty **)malloc(G.files.size * sizeof *list);
		DIE_IF(!list && G.files.size > 0, "%s", "Out of memory.\n");
		size_t nfiles = 0;
		for (i = 0; i < G.files.size; ++i) {
			file_ty *file = &G.files.data[i];
			if (file_filter_pass(file, &G.interactive_files_buf))
				list[nfiles++] = file;
		}
		if (nfiles > 0) {
			root_ctx_ty root;
			root.kind = FAR_ROOT_MEM;
			root.path = NULL;
			memset(&root.st, 0, sizeof root.st);
			root.mem_files = list;
			root.mem_count = nfiles;
			root.a = a;
			root.t = t;
			const size_t before = a->err_count;
			if (jstr_chk(pipeline_run(&root)) || a->err_count > before)
				jstr_errdie("find-and-replace: error processing cached files (find=\"%s\", replace=\"%s\").\n", a->find, a->rplc);
		}
		free(list);
	}
}

/* Process stdin fallback when no file argument was passed. */
/**
 * @anchor spec_process_no_files_stdin
 * @brief Run the implicit stdin target when no files were given.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param a parsed CLI arguments.
 * @param t compiled fixed-string matcher.
 * @param argv argument vector.
 * @return `JSTR_RET_SUCC` on success; otherwise a typed error code.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
static jstr_ret_ty
process_no_files_stdin(args_ty *a, jstr_twoway_ty *t, char **argv)
{
	if (jstr_unlikely(G.bak_suffix != NULL) || jstr_unlikely(G.output_mode != OUT_STDOUT))
		jstr_errdie("%s: %s", argv[0], "find-and-replace: trying to create a backup file while reading from stdin.");
	if (jstr_unlikely(G.mode & MODE_USE_RECURSIVE))
		jstr_errdie("%s: %s", argv[0], "trying to recursively traverse through directories while reading from stdin.");
	if (a->find_len == 0 && (G.mode & MODE_GREP)) {
		G.grep_matched = 1;
		return JSTR_RET_SUCC;
	}
	if (a->find_len != 0)
		compile_or_die(t, a->find, a->find_len, a->rplc, a->rplc_len);
	a->confirm_phase = CONFIRM_NONE;
	root_ctx_ty root;
	root.kind = FAR_ROOT_STDIN;
	root.path = NULL;
	memset(&root.st, 0, sizeof root.st);
	root.mem_files = NULL;
	root.mem_count = 0;
	root.a = a;
	root.t = t;
	const size_t before = a->err_count;
	if (jstr_chk(pipeline_run(&root)) || a->err_count > before) {
		if (G.mode & MODE_GREP)
			fprintf(stderr, "%s", "Failed grep on stdin.\n");
		else
			fprintf(stderr, "%s", "Failed processing stdin.\n");
		return JSTR_RET_ERR;
	}
	return JSTR_RET_SUCC;
}

/**
 * @anchor spec_main
 * @brief Program entry point: parse, dispatch, and return the final exit code.
 *
 * @details This function is part of the main.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param argc argument count.
 * @param argv argument vector.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Main thread only.
 */
int
main(int argc, char **argv)
{
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
	a.confirm_phase = CONFIRM_NONE;
	jstr_twoway_ty t;
	a.t = &t;
	a.find = (const char *)FIND;
	const char *raw_find = (const char *)FIND;
	a.find_len = JSTR_DIFF(jstr_unescape_p(FIND), FIND);
	const char *raw_rplc;
	/* If argv[2] starts with '-', it's a flag, not REPLACE.  Allow grep/confirm
	 * modes to omit the REPLACE argument. */
	unsigned int i;
	a.rplc = (const char *)RPLC;
	raw_rplc = (const char *)RPLC;
	a.rplc_len = JSTR_DIFF(jstr_unescape_p(RPLC), RPLC);
	init_defaults();
	G.confirm_pass = 1;
	preparse_workers(argc, argv);
	if (jstr_unlikely(pipeline_start() != 0))
		jstr_errdie("%s", "Can't start the pipeline threads.\n");
	parser_state_ty parser_state = PARSE_FLAGS;
	file_batch_ty batch = { 0 };
	for (i = 3; ARG; ++i) {
		if (*ARG == '-' && ARG[1] != '\0' && parser_state == PARSE_FLAGS) {
			flush_file_batch(&a, &t, &batch);
			if (ARG[1] == 'j') {
				const char *val = ARG[2] != '\0' ? ARG + 2 : argv[++i];
				pipeline_set_workers(parse_workers_value(argv[0], val));
				continue;
			}
			if (ARG[1] == 'i') {
				if (ARG[2] == '\0') {
					G.output_mode = OUT_INPLACE;
				} else {
					G.bak_suffix = ARG + S_LEN("-i");
					G.bak_suffix_len = strlen(G.bak_suffix);
					G.output_mode = OUT_BACKUP;
				}
				check_grep_conflicts();
				continue;
			}
			if (ARG[1] == '-') {
				if (parse_long_flag(argv, &i, &parser_state))
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
			flush_file_batch(&a, &t, &batch);
			(void)process_stdin_arg(&a, &t, argv[0]);
			continue;
		}
		process_target_arg(ARG, &a, &t, &batch);
	}
	flush_file_batch(&a, &t, &batch);
	free(batch.data);
	if (jstr_unlikely((G.mode & MODE_GREP) && ((G.mode & MODE_CONFIRM) || G.output_mode != OUT_STDOUT))) {
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
			if (jstr_unlikely(pipeline_ui_finish() < 0)) {
				cleanup();
				return err_exit_code();
			}
		}
		cleanup();
		return G.grep_matched ? EXIT_SUCCESS : EXIT_FAILURE;
	}
	cleanup();
	return EXIT_SUCCESS;
	(void)argc;
}
