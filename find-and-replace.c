/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#define JSTR_PANIC                0
#define JSTR_USE_UNLOCKED_IO_READ 1

#include <jstr/jstr.h>
#include <jstr/io.h>
#include <jstr/regex.h>

#define S_LEN(s)     (sizeof(s) - 1)
#define S_LITERAL(s) (s), (sizeof(s) - 1)

#include <fnmatch.h>

#define DIE_IF_PRINT(x, fmt, ...)                      \
	do {                                           \
		if (jstr_unlikely(x))                  \
			jstr_errdie(fmt, __VA_ARGS__); \
	} while (0)
#define DIE_IF(x, fmt, ...) DIE_IF_PRINT(x, fmt, __VA_ARGS__)
#define DIE()               DIE_IF(1)
#define ARG                 argv[i]
#define ARG_NEXT()          ++i
#define ARG_PREV()          --i
#define IS_REG(x)           S_ISREG(x)
#define IS_DIR(x)           S_ISDIR(x)
#define FIND                argv[1]
#define RPLC                argv[2]
#define R                   JSTR_RESTRICT

#define _(x) x
#define SEP  '/'

#define DO_FREE 0

#define ARG_START_IDX       3
#define INITIAL_MATCHES_CAP 16
#define ANSWER_BUF_SIZE     100
#define COLOR_RED           "\x1b[31m"
#define COLOR_GREEN         "\x1b[32m"
#define COLOR_RESET         "\x1b[0m"

typedef enum {
	MODE_PRINT_STDOUT = 1 << 0,
	MODE_PRINT_FILE = 1 << 1,
	MODE_PRINT_FILE_BACKUP = 1 << 2,
	MODE_PRINT_CHANGES = 1 << 3,
	MODE_USE_RECURSIVE = 1 << 4,
	MODE_USE_REGEX = 1 << 5,
	MODE_COMPILED = 1 << 6,
	MODE_HAVE_FILES = 1 << 7,
} mode_ty;

typedef struct global_ty {
	const char *include_glob;
	const char *bak_suffix;
	size_t bak_suffix_len;
	size_t n;
	int mode;
	int cflags;
	int eflags;
	int confirm;
	jstr_re_ty regex;
} global_ty;
global_ty G = { .mode = MODE_PRINT_STDOUT };

int G_confirm_pass = 0;
int G_matches_found = 0;

JSTR_FUNC
static jstr_ret_ty
xstat(const char *R file,
      struct stat *R buf)
{
	if (jstr_unlikely(stat(file, buf)))
		goto err;
	return JSTR_RET_SUCC;
err:
	JSTR_RETURN_ERR(JSTR_RET_ERR);
}

static int
file_exists(const char *R fname)
{
	return access(fname, F_OK) == 0;
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

/* static ft_ty */
/* exttype(const char *fname, size_t fname_len) */
/* { */
/* 	fname = jstr_memrchr(fname, '.', fname_len); */
/* 	if (fname != NULL && *++fname != '\0') { */
/* 		static const char *textv[] = { "C", "S", "c", "cc", "cs", "cpp", "h", "hh", "hpp", "html", "js", "json", "md", "pl", "pm", "py", "pyi", "rs", "s", "sh", "ts", "txt" }; */
/* 		static const char *binv[] = { "a", "bin", "gz", "jpg", "jpeg", "mp4", "mp3", "mkv", "o", "pdf", "png", "pyc", "rar", "so", "wav", "zip" }; */
/* 		unsigned int i; */
/* 		for (i = 0; i < sizeof(textv) / sizeof(*textv); ++i) */
/* 			if (!jstr_strcmpeq_loop(fname, textv[i])) */
/* 				return FT_TEXT; */
/* 		for (i = 0; i < sizeof(binv) / sizeof(*binv); ++i) */
/* 			if (!jstr_strcmpeq_loop(fname, binv[i])) */
/* 				return FT_BINARY; */
/* 	} */
/* 	return FT_UNKNOWN; */
/* } */

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
	union u {
		size_t zu;
		jstr_re_off_ty d;
	} changed;
	int fd_tmp = -1;
	char *bakp = NULL;
	char bak[JSTR_IO_PATH_MAX];
	if (G.mode & MODE_USE_REGEX) {
		if (jstr_unlikely(find_len == 0)) {
			changed.zu = 0;
		} else {
			changed.d = jstr_re_rplcn_backref_len_exec_j(&G.regex, buf, rplc, rplc_len, G.eflags, 10, G.n);
			if (jstr_re_chk(changed.d)) {
				jstr_re_errdie(changed.d, &G.regex, "%s", "Regex replacement failed.\n");
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
			changed.zu = (size_t)changed.d;
		}
	} else {
		changed.zu = jstr_rplcn_len_exec_j(t, buf, find, find_len, rplc, rplc_len, G.n);
		if (jstr_unlikely(changed.zu == (size_t)-1))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	}
	/* Append newline if has space */
	if (buf->size && buf->data[buf->size - 1] != '\n' && buf->capacity >= buf->size + S_LEN("\n") + 1)
		buf->size = JSTR_PTR_DIFF(jstr_append_len_unsafe_p(buf->data, buf->size, "\n", 1), buf->data);
	if (G.mode & MODE_PRINT_STDOUT) {
		if (jstr_unlikely(jstr_io_fwrite(buf->data, 1, buf->size, stdout) != buf->size))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	} else {
		if (changed.zu == 0)
			return JSTR_RET_SUCC;
		if (G.mode & MODE_PRINT_FILE_BACKUP) {
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
		if (G.mode & MODE_PRINT_CHANGES) {
			if (jstr_chk(jstr_io_fwrite(fname, 1, fname_len, stdout)))
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

typedef struct {
	size_t start;
	size_t end;
} match_t;

static void
add_match(match_t **matches, size_t *cap, size_t *cnt, size_t start, size_t end)
{
	if (*cnt >= *cap) {
		*cap = *cap == 0 ? INITIAL_MATCHES_CAP : *cap * 2;
		match_t *new_matches = realloc(*matches, *cap * sizeof(match_t));
		DIE_IF(!new_matches, "%s", "Out of memory allocating matches.\n");
		*matches = new_matches;
	}
	(*matches)[*cnt].start = start;
	(*matches)[*cnt].end = end;
	(*cnt)++;
}

static size_t
get_line_start(const char *data, size_t file_size, size_t idx)
{
	if (idx == 0) return 0;
	if (idx > file_size) idx = file_size;
	size_t i = idx;
	while (i > 0) {
		if (data[i - 1] == '\n') {
			return i;
		}
		i--;
	}
	return 0;
}

static size_t
get_line_end(const char *data, size_t file_size, size_t idx)
{
	if (idx >= file_size) return file_size;
	size_t i = idx;
	while (i < file_size) {
		if (data[i] == '\n') {
			return i;
		}
		i++;
	}
	return file_size;
}

static size_t
get_line_number(const char *data, size_t idx)
{
	size_t line_num = 1;
	for (size_t i = 0; i < idx; ++i) {
		if (data[i] == '\n') {
			line_num++;
		}
	}
	return line_num;
}

static void
print_size_t(size_t val)
{
	char buf[32];
	size_t idx = sizeof(buf);
	if (val == 0) {
		buf[--idx] = '0';
	} else {
		while (val > 0) {
			buf[--idx] = '0' + (val % 10);
			val /= 10;
		}
	}
	jstr_io_fwrite(buf + idx, 1, sizeof(buf) - idx, stdout);
}

static void
print_segment(const char *data, size_t len, const char *fname, size_t *curr_line_num, int *at_line_start)
{
	for (size_t i = 0; i < len; ++i) {
		if (*at_line_start) {
			jstr_io_fwrite(fname, 1, strlen(fname), stdout);
			jstr_io_putchar(':');
			print_size_t(*curr_line_num);
			jstr_io_putchar(':');
			*at_line_start = 0;
		}
		jstr_io_putchar(data[i]);
		if (data[i] == '\n') {
			(*curr_line_num)++;
			*at_line_start = 1;
		}
	}
}

static jstr_ret_ty
confirm_scan_file(const jstr_twoway_ty *R t,
                  const jstr_ty *R buf,
                  const char *R fname,
                  size_t fname_len,
                  const char *R find,
                  const size_t find_len,
                  const char *R rplc,
                  const size_t rplc_len)
{
	match_t *matches = NULL;
	size_t matches_cap = 0;
	size_t matches_cnt = 0;

	if (G.mode & MODE_USE_REGEX) {
		if (find_len > 0) {
			size_t curr = 0;
			regmatch_t rm;
			int eflags = G.eflags;
			while (curr < buf->size) {
				int r = jstr_re_exec_len(&G.regex, buf->data + curr, buf->size - curr, 1, &rm, eflags | (curr > 0 ? REG_NOTBOL : 0));
				if (r == JSTR_RE_RET_NOMATCH) break;
				if (r != JSTR_RE_RET_NOERROR) {
					break;
				}
				size_t m_start = curr + rm.rm_so;
				size_t m_end = curr + rm.rm_eo;
				add_match(&matches, &matches_cap, &matches_cnt, m_start, m_end);
				curr = m_end;
				if (rm.rm_eo == rm.rm_so) {
					curr++;
				}
				if (G.n == 1) break;
			}
		}
	} else {
		if (find_len > 0) {
			size_t curr = 0;
			while (curr < buf->size) {
				const char *p = jstr_memmem_exec(t, buf->data + curr, buf->size - curr, find, find_len);
				if (!p) break;
				size_t m_start = p - buf->data;
				size_t m_end = m_start + find_len;
				add_match(&matches, &matches_cap, &matches_cnt, m_start, m_end);
				curr = m_end;
				if (G.n == 1) break;
			}
		}
	}

	if (matches_cnt > 0) {
		G_matches_found = 1;
		size_t start_idx = 0;
		while (start_idx < matches_cnt) {
			size_t end_idx = start_idx;
			while (end_idx + 1 < matches_cnt) {
				size_t prev_line_end = get_line_end(buf->data, buf->size, matches[end_idx].end);
				size_t curr_line_start = get_line_start(buf->data, buf->size, matches[end_idx + 1].start);
				if (curr_line_start <= prev_line_end) {
					end_idx++;
				} else {
					break;
				}
			}

			size_t block_start = get_line_start(buf->data, buf->size, matches[start_idx].start);
			size_t block_end = get_line_end(buf->data, buf->size, matches[end_idx].end);
			size_t line_num = get_line_number(buf->data, matches[start_idx].start);

			size_t curr_line_num = line_num;
			int at_line_start = 1;
			size_t p = block_start;
			for (size_t k = start_idx; k <= end_idx; ++k) {
				if (matches[k].start > p) {
					print_segment(buf->data + p, matches[k].start - p, fname, &curr_line_num, &at_line_start);
				}
				jstr_io_fwrite(COLOR_RED, 1, strlen(COLOR_RED), stdout);
				print_segment(buf->data + matches[k].start, matches[k].end - matches[k].start, fname, &curr_line_num, &at_line_start);
				jstr_io_fwrite(COLOR_RESET, 1, strlen(COLOR_RESET), stdout);

				jstr_io_fwrite(COLOR_GREEN, 1, strlen(COLOR_GREEN), stdout);
				print_segment(rplc, rplc_len, fname, &curr_line_num, &at_line_start);
				jstr_io_fwrite(COLOR_RESET, 1, strlen(COLOR_RESET), stdout);

				p = matches[k].end;
			}
			if (block_end > p) {
				print_segment(buf->data + p, block_end - p, fname, &curr_line_num, &at_line_start);
			}
			jstr_io_putchar('\n');

			start_idx = end_idx + 1;
		}
		free(matches);
	}

	return JSTR_RET_SUCC;
	(void)fname_len;
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
	const size_t file_size = (size_t)st->st_size;
	if (!(G.mode & MODE_USE_REGEX) && file_size < find_len)
		return JSTR_RET_SUCC;
#if 0
	const ft_ty ft = exttype(fname, fname_len);
	f (ft == FT_BINARY)
		return JSTR_RET_SUCC;
#endif
	/* Preallocate the length of the replace string. */
	if (rplc_len > find_len && !(G.mode & MODE_USE_REGEX))
		if (jstr_chk(jstr_reserve_j(buf, file_size + rplc_len - find_len + S_LEN("\n") + 1)))
			JSTR_RETURN_ERR(JSTR_RET_ERR);
	if (jstr_chk(jstr_io_readfile_len_j(buf, fname, 0, file_size)))
		JSTR_RETURN_ERR(JSTR_RET_ERR);

	if (G_confirm_pass) {
		return confirm_scan_file(t, buf, fname, fname_len, find, find_len, rplc, rplc_len);
	}

#if 0
	if (ft == FT_UNKNOWN)
		if (jstr_io_isbinary(buf->data, JSTR_MIN(64, file_size)))
			return JSTR_RET_SUCC;
#endif
	jstr_ret_ty ret = process_buffer(t, buf, fname, fname_len, st, find, find_len, rplc, rplc_len);
	return ret;
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
	if (!(G.mode & MODE_COMPILED)) {
		if (G.mode & MODE_USE_REGEX) {
			const int ret = jstr_re_comp(&G.regex, find, G.cflags);
			if (jstr_unlikely(ret != JSTR_RE_RET_NOERROR)) {
				jstr_re_err(ret, &G.regex, "regex compilation failed for pattern \"%s\".\n", find);
				JSTR_RETURN_ERR(JSTR_RET_ERR);
			}
		} else {
			jstr_memmem_comp(t, find, find_len);
		}
		G.mode |= MODE_COMPILED;
	}
	return JSTR_RET_SUCC;
}

/* Default flags. */
void
init_defaults()
{
	/* Anchors match on newlines. */
	G.cflags |= JSTR_RE_CF_NEWLINE;
	/* Non-global replacement. */
	G.n = 1;
}

/* clang-format off */

const char *usage =
	_("Usage: find-and-replace [FIND] [REPLACE] [OPTIONS]... [FILES]...\n")
	_("Options:\n")
	_("  -G (default)\n")
	_("    Replace first occurence of FIND with REPLACE.\n")
	_("  -g\n")
	_("    Replace all occurrences of FIND with REPLACE, negates -G flag.\n")
	_("  -i[SUFFIX]\n")
	_("    Replace files in-place. The default is printing to stdout.\n")
	_("    If SUFFIX is provided, backup the original file suffixed with SUFFIX.\n")
	_("  -c\n")
	_("    Confirm functionality. Displays all proposed replacements and asks\n")
	_("    for user confirmation ('y') before modifying files in-place.\n")
	_("  -r\n")
	_("    Recurse on the directories in FILES.\n")
	_("  --include GLOB\n")
	_("    File glob to match when -r is used. Glob is a wildcard.\n")
	_("  --exclude GLOB\n")
	_("    The reverse of --include. Skip files that match glob.\n")
	_("    This applies to the passed command line files.\n")
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

int
main(int argc, char **argv)
{
	if (jstr_nullchk(argv[1])) {
		jstr_io_fwrite(usage, 1, strlen(usage), stderr);
		return EXIT_FAILURE;
	}
	if (jstr_nullchk(argv[2])) {
		/* -h */
		FILE *fp = stderr;
		int ret = EXIT_FAILURE;
		if (!strcmp(argv[1], "-h")) {
			fp = stdout;
			ret = EXIT_SUCCESS;
		}
		jstr_io_fwrite(usage, 1, strlen(usage), fp);
		return ret;
	}
	struct stat st;
	int ret;
	args_ty a;
	matcher_args_ty m;
	jstr_twoway_ty t;
	a.t = &t;
	a.find = (const char *)FIND;
	a.rplc = (const char *)RPLC;
	a.find_len = JSTR_DIFF(jstr_unescape_p(FIND), FIND);
	a.rplc_len = JSTR_DIFF(jstr_unescape_p(RPLC), RPLC);
	m.include_glob = NULL;
	m.exclude_glob = NULL;
	jstr_ty buf = JSTR_INIT;
	init_defaults();
	{
		int has_confirm = 0;
		int j;
		for (j = ARG_START_IDX; j < argc; ++j) {
			if (strcmp(argv[j], "--") == 0) {
				break;
			}
			if (argv[j][0] == '-' && argv[j][1] != '-') {
				if (strchr(argv[j], 'c')) {
					has_confirm = 1;
					break;
				}
			}
		}
		G.confirm = has_confirm;
	}
	if (G.confirm) {
		G_confirm_pass = 1;
	} else {
		G_confirm_pass = 0;
	}

run_pass:;
	int end_of_flags = 0;
	unsigned int i;
	/* Process all arguments: flags then files, in order. */
	for (i = ARG_START_IDX; ARG; ++i) {
		if (*ARG == '-' && !end_of_flags) {
			/* -i[SUFFIX] */
			if (ARG[1] == 'i') {
				if (ARG[2] == '\0') {
					G.mode = (G.mode & ~MODE_PRINT_STDOUT) | MODE_PRINT_FILE;
				} else {
					G.bak_suffix = ARG + sizeof("-i") - 1;
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
					m.include_glob = ARG;
					continue;
				}
				/* --exclude */
				if (!strcmp(ARG + 2, "exclude")) {
					ARG_NEXT();
					if (jstr_nullchk(ARG))
						jstr_errdie("%s: %s", argv[0], "no argument after --exclude flag.\n");
					m.exclude_glob = ARG;
					continue;
				}
				/* bare "--": stop flag parsing */
				if (ARG[2] == '\0') {
					end_of_flags = 1;
					continue;
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
use_regex_flag:
						G.mode |= MODE_USE_REGEX;
						break;
					case 'Z':
						G.cflags |= JSTR_RE_CF_NEWLINE;
						break;
					case 'g':
						G.n = (size_t)-1;
						break;
					case 'h':
						jstr_io_fwrite(usage, 1, strlen(usage), stdout);
						exit(EXIT_SUCCESS);
						break;
					case 'c':
						G.confirm = 1;
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
					default:
						jstr_io_fwrite("find-and-replace: invalid flag '-", 1, S_LEN("find-and-replace: invalid flag '-"), stderr);
						jstr_io_putchar(*argp);
						jstr_io_fwrite("'. See usage below:\n\n", 1, S_LEN("'. See usage below:\n\n"), stderr);
						jstr_io_fwrite(usage, 1, strlen(usage), stderr);
						exit(EXIT_FAILURE);
						break;
					}
				}
done_single:;
			}
			continue;
		}
		G.mode |= MODE_HAVE_FILES;
		ret = xstat(ARG, &st);
		DIE_IF(ret == JSTR_RET_ERR, "stat(%s) failed.\n", ARG);
		DIE_IF(jstr_chk(compile(&t, a.find, a.find_len)), "%s", "");
		if (IS_REG(st.st_mode)) {
			const size_t fname_len = strlen(ARG);
			if (!m.exclude_glob) {
process:
				DIE_IF(jstr_chk(process_file(&t, &buf, ARG, fname_len, &st, a.find, a.find_len, a.rplc, a.rplc_len)), "find-and-replace: error processing '%s' (find=\"%s\", replace=\"%s\").\n", ARG, a.find, a.rplc);
			} else {
				const char *fname = jstr_memrchr(ARG, SEP, fname_len);
				fname = (fname != NULL && *(fname + 1)) ? fname + 1 : ARG;
				if (fnmatch(m.exclude_glob, fname, 0))
					goto process;
			}
		} else if (IS_DIR(st.st_mode)) {
			if (G.mode & MODE_USE_RECURSIVE) {
				a.buf = &buf;
				DIE_IF(jstr_chk(jstr_io_ftw(ARG, callback_file, &a, JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG, (m.include_glob || m.exclude_glob) ? matcher : NULL, &m)), "ftw(directory: %s, callback, func_args, flags: JSTR_IO_FTW_REG | JSTR_IO_FTW_STATREG, matcher: %s, matcher_args) failed.\n", ARG, m.include_glob ? "1" : "0");
			}
		} else {
			jstr_io_fwrite("find-and-replace: ", 1, S_LEN("find-and-replace: "), stderr);
			jstr_io_fwrite(ARG, 1, strlen(ARG), stderr);
			jstr_io_fwrite(" is not a regular file or directory.\n", 1, S_LEN(" is not a regular file or directory.\n"), stderr);
			exit(EXIT_FAILURE);
		}
	}
	if (G_confirm_pass) {
		if (!(G.mode & (MODE_PRINT_FILE | MODE_PRINT_FILE_BACKUP))) {
			jstr_errdie("%s: -c requires -i\n", argv[0]);
		}
		if (!(G.mode & MODE_HAVE_FILES)) {
			jstr_errdie("%s: -c does not work with stdin\n", argv[0]);
		}
		if (G_matches_found) {
			jstr_io_fwrite("Confirm changes? [y/N]: ", 1, S_LEN("Confirm changes? [y/N]: "), stdout);
			jstr_io_fflush(stdout);
			int c = jstr_io_getchar();
			if (c != 'y') {
				jstr_io_fwrite("Aborted.\n", 1, S_LEN("Aborted.\n"), stderr);
				exit(EXIT_FAILURE);
			}
			G_confirm_pass = 0;
			G.mode &= ~MODE_HAVE_FILES;
			if (G.mode & MODE_USE_REGEX) {
				jstr_re_free(&G.regex);
			}
			G.mode &= ~MODE_COMPILED;
			jstr_free_j(&buf);
			buf = (jstr_ty)JSTR_INIT;
			goto run_pass;
		} else {
			return EXIT_SUCCESS;
		}
	}
	/* If no file was passed, read from stdin. */
	if (!(G.mode & MODE_HAVE_FILES)) {
		if (jstr_unlikely(G.bak_suffix != NULL) || jstr_unlikely(!(G.mode & MODE_PRINT_STDOUT)))
			jstr_errdie("%s: %s", argv[0], "find-and-replace: trying to create a backup file while reading from stdin.");
		if (jstr_unlikely(G.mode & MODE_USE_RECURSIVE))
			jstr_errdie("%s: %s", argv[0], "trying to recursively traverse through directories while reading from stdin.");
		DIE_IF(jstr_chk(jstr_io_readstdin_j(&buf)), "%s", "Failed reading stdin.\n");
		DIE_IF(jstr_chk(compile(&t, a.find, a.find_len)), "%s", "");
		DIE_IF(jstr_chk(process_buffer(&t, &buf, NULL, 0, NULL, a.find, a.find_len, a.rplc, a.rplc_len)), "%s", "Failed processing stdin.\n");
	}
#if DO_FREE /* We don't need to free since we're exiting. */
	jstr_re_free(&G.regex);
	jstr_free_j(&buf);
#endif
	return EXIT_SUCCESS;
	(void)argc;
}
