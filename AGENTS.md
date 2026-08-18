# find-and-replace

Multi-file C CLI tool (common header `common.h` + `main.c`, `files.c`,
`process.c`, `confirm.c`, ~1100 lines) for fixed-string or regex
find-and-replace on files, with optional recursion, regex filtering of
basenames via `--include`/`--exclude`, and in-place editing with backups.

## Setup & build

```
sudo ./setup   # clones lib/jstring from github.com/IAKOBVS/jstring, compiles + tests it
./compile      # parallel-compiles the 4 translation units, links against lib/jstring/build/lib/libjstr.so
sudo ./install # copies binary to $HOME/.local/bin (dir must exist)
```

- `./compile` compiles all `*.c` units **in parallel** (`cc -c ... &` + `wait`), then links
- `COVERAGE=1 ./compile` builds with `--coverage` flags for `gcov` analysis
- `./update` runs `git restore && ./update` inside `lib/jstring` (update jstring dependency)
- `./generate-readme` rebuilds `README.md` from `.README.md` + usage strings in `main.c`
- `./coverage` builds with coverage, runs all tests, and runs `gcov` on all 4 units

## Source layout

| File | Purpose |
|---|---|
| `common.h` | Includes, shared macros (`DIE_IF`, `S_LEN`, `R`, MODE_* bits), core types (`mode_ty`, `match_ty`, `matches_ty`, `file_ty`, `files_ty`, `global_ty`), `extern global_ty G` |
| `files.h` | `args_ty`, `matcher_args_ty`, `FILE_CACHE_MAX`/`FILES_CAP_MIN`, prototypes for `xstat`, `file_exists`, `callback_file`, `matcher`, `file_pushback` |
| `process.h` | Prototypes for `process_buffer`, `process_file` |
| `confirm.h` | Colors/prompt macros, `MATCHES_CAP_MIN`, prototype for `confirm_scan_file` |
| `main.c` | `main`, flag/file-argument parsing, `usage`, `compile`, `init_defaults`, `cleanup`; defines `G` |
| `files.c` | `xstat`, `file_exists`, ftw callbacks (`callback_file`, `matcher`), `ft_ty` |
| `process.c` | `process_buffer`, `process_file` |
| `confirm.c` | `-c` scan/preview: `confirm_scan_file`, `match_pushback`, `file_pushback`, line helpers, printers |

Related functions share a namespace prefix (`process_*`, `match_*`, `line_*`,
`print_*`, `file_*`, `confirm_*`); types keep their original names (`mode_ty`,
`match_ty`, ...) and the global is `global_ty G`. Only functions called across
TUs are non-static; their prototypes live in the module headers
(`files.h`/`process.h`/`confirm.h`, all of which include `common.h`).

## Key facts

- **Only ANSI C features** - no VLAs, no `//` comments, no C99+ features beyond what POSIX requires
- **Dependency**: [jstring](https://github.com/IAKOBVS/jstring) - linked via `lib/jstring/build/lib/libjstr.so`
- **Include path**: `lib/jstring/build/include/` passed via `-I` (pinned checkout, not `/usr/local/include`)
- **Code style**: no comments, SPDX MIT header, `clang-format off/on` around the usage string
- **Brace style**: a single statement in `if`/`else`/`for`/`while`/`do` needs no wrapping braces (e.g. `if (x) return;`); braces are only used when the block has two or more statements. The statement must go on the **next line** — never on the same line as the condition (`if (x) return;` on one line is disallowed). In an `if`/`else if`/`else` chain, braces must be **uniform**: if one branch needs braces (two or more statements), then every branch gets braces — even the single-statement ones
- **Python test scripts**: every function, parameter, and local variable must be
  fully type annotated (PEP 484, `typing` imports). Verify with `mypy
  tests/pty_drive.py` — the shared pty driver is mypy-clean.
- **Usage strings** are defined with `_(...)` macro calls in `main.c`; `generate-readme` parses these with `grep '_('`
- `.gitignore` ignores `find-and-replace` binary, `*.o`, and `jstring/` (symlink/lib dir)
- **No linter/formatter** beyond compiler flags (`-Wall -Wextra -Wpedantic`)
- **No CI** workflows
- **Coding style / Performance**: Use `jstr_unlikely` for all error or unlikely execution paths to aid compiler branch prediction. Use `memcmp` instead of `strncmp` when key length is known and bounded to avoid unnecessary null-termination checks.
- **jstring .so gotcha**: `lib/jstring/scripts/test` rebuilds `libjstr.so` with
  `-fsanitize=address`. Re-run `lib/jstring/./compile` (non-ASan) after any
  jstring `./test` run, before linking the tool.
- **`sudo ./install` in `lib/jstring` is optional**: the tool compiles against
  the pinned `lib/jstring/build/{include,lib}`, so `/usr/local` copies may be stale.

## Tests

```
./compile && tests/run.sh   # all deterministic suites (14 suites, 308 tests)
./test [N]                  # all tests + N fuzz iterations (default 250)
./tests/basic.sh            # run a single suite independently
./tests/fuzz.sh [N]         # fuzz tests only (default 500)
./coverage                  # build with --coverage, run all tests, report gcov
```

### Test suites

| Suite | File | Tests | Coverage |
|---|---|---|---|
| Basic | `tests/basic.sh` | 17 | Fixed stdin, global, in-place/backup, explicit G, no-match, empty/find-equal/longer replace, combined `-ir` |
| Flags | `tests/flags.sh` | 25 | `-F -R -E -I -Z -z -g -G -h`, flag ordering (F/R, Z/z, g/G), flags between files, `--version`, `-l`, `-q`/`--quiet`, `--exclude` CLI errors |
| Regex | `tests/regex.sh` | 16 | BRE/ERE, backreferences (incl. exceeding nsub), anchors with `-Z`/`-z`, regex in in-place, escape in regex |
| Files | `tests/files.sh` | 33 | Multi-file, recursive, `--include`/`--exclude` regexes, dash filenames, deep/many-file recursion, `-` stdin placeholder |
| Errors | `tests/errors.sh` | 23 | Missing args, nonexistent file, invalid flag/regex, backup collision, long suffix, stdin+in-place/recursive, read-only, SIGXFSZ/SIGPIPE fault injection |
| IO | `tests/io.sh` | 21 | Backup identity/empty/binary/multi, in-place shorter/longer/same/identical, binary, FIFO, read-only, large stdin, stdout multi-file |
| Escape | `tests/escape.sh` | 9 | `\t \b \f \n \r \v \octal` in find and replace |
| Empty | `tests/empty.sh` | 5 | Empty find in stdin, file, in-place, regex, global modes |
| Misc | `tests/misc.sh` | 7 | Double-dash, multiline find, slash literal, overlapping, end-of-options |
| Edge cases | `tests/edge-cases.sh` | 18 | Empty input, missing newlines, invalid regex, overlapping, empty lines, null bytes, massive lines, long replacements, UTF-8, read-only backup, nonexistent dir |
| Complex regex | `tests/complex.sh` | 14 | Backreferences (reorder, nested groups, XML tags, alternation, max digits), IP/URL/email parsing, greedy, quantifiers |
| Confirm | `tests/confirm.sh` | 87 | `-c` preview: diff format lines, backrefs, multi-line, same-line grouping, recursive, backup, no-match, prompt yes/no, unconditional colors, interactive TUI (all 7 fields, vim motions, height capping, tab expansion, no-scroll, controls pinned, Ctrl-J/K scroll past vis_end) |
| Grep | `tests/grep.sh` | 28 | `--grep`: stdin/file/recursive, exit codes 0/1/2, `-i`/`-c` conflicts, `-q`, `-` stdin placeholder, binary skip, anchors, empty find, match highlight, interactive TUI (launch, scroll, exclude, Ctrl-D, multiline, file-cache, FIND field, pinned controls, vim mode) |
| Unit | `tests/unit.sh` | 6 | Internal unit tests (procfs/meminfo helper shim) |
| Fuzz | `tests/fuzz.sh` | N | Random strings with random flags; detects crashes and unexpected non-zero exits |

### Test categories

The category files partition tests by functionality rather than strict line coverage boundaries. Some overlap exists (e.g., regex used in in-place mode lives in `regex.sh`, not `io.sh`). Representative tests and coverage areas listed in the suites table above.

### Test writing conventions

All tests follow the same conventions:

- **Each test is a shell function** that takes a single argument (`$1`) — a temporary directory unique to that test. The function stores it as `td=$1`.
- **Results are written to `$1/result`** — the string `PASS` on success, or `FAIL: <reason>` on failure.
- **The binary path** is available as `$PROG` (set in `tests/lib.sh`, sourced by all test files).
- **Stderr is redirected to `/dev/null`** (`2>/dev/null`) unless the test specifically checks error output.
- **Tests are registered** by listing their function name in the `TESTS` variable. Only listed functions are executed by the runner.
- **Every bug gets a regression test.** When a bug is found and fixed, add a test that specifically exercises the broken code path. Name it descriptively (e.g. `t_grep_interactive_file_cache` for the file-caching ordering bug) and comment the root cause at the top of the test function.

### Test runner parallelism

The test scripts use a batch-wait jobserver to limit concurrency and avoid file descriptor exhaustion, implemented in `tests/lib.sh`:

```
MAX_JOBS=${FAR_MAX_JOBS:-512}
count=0
for t in $TESTS; do
    (
        mkdir -p "$td_root/$t"
        "$t" "$td_root/$t"
    ) &
    launched="$launched $t"
    count=$((count + 1))
    if [ "$count" -ge "$MAX_JOBS" ]; then
        wait_for_results "$launched"
        launched=""
        count=0
    fi
done
[ "$count" -gt 0 ] && wait_for_results "$launched"
```

Each test runs as a background subshell that is guaranteed to write a result
file (the `run_tests` wrapper records a `FAIL: no result written` fallback if
the test function dies without one). `wait_for_results` polls the result files
and prints `report_result` — `t_foo PASS` / `t_foo FAIL (...)` — **the moment
each test finishes**, so PASS/FAIL stream on the fly instead of being dumped
after the whole batch. A trailing `wait` reaps the subshells. `MAX_JOBS` (512
by default, override with `FAR_MAX_JOBS` for low-`ulimit -n` systems) caps
concurrency to avoid file descriptor exhaustion.

All 13 deterministic suites run in order via `tests/run.sh`, each suite's
progressive per-test output streaming straight to the terminal (no log
capture); each suite keeps its own internal batch-wait jobserver for
test-level parallelism, and run.sh exits non-zero if any suite failed.
Interactive TUI tests drive the binary through `tests/pty_drive.py` (typed
driver, mypy-clean), which creates the pty, applies
`--winsize` to the slave **before** forking (no race with the child's first
render), feeds `--phase`/`--tail` keystrokes, and reports the child's real exit
status (including a non-blocking reap + EIO-safe read on early marker-miss).

### Coverage: 95.5% of executable lines

Coverage measured via `gcov` (`./coverage`, branch + line) after running all
308 deterministic tests: 95.5% lines (1389/1454), 99.1% branches executed,
80.6% of branches taken both ways (6 sources: main, files, process, confirm,
procfs, vim). The small drop from Session 11's 95.9% comes from the new
grep/`-`-stdin code paths that need fault injection or tty input to hit
(e.g. the `-c`/`-r` + `-` conflict errors, ftw-failure exit).

**Covered paths include:**
- All flag parsing (`-F -G -g -R -E -I -Z -z -r -h`) and `--` end-of-flags
- All flag combinations and last-wins ordering
- Fixed-string and regex replacement (BRE and ERE)
- In-place editing with and without backup suffix
- Backup suffix collision detection
- `--include` regex filtering during recursion
- `--exclude` filtering on CLI files and during recursion
- Combined `--include` + `--exclude` during recursion
- Escape sequences: `\b`, `\f`, `\n`, `\r`, `\t`, `\v`, octal
- Multi-line find and replace
- Binary file detection and skipping
- Error paths: missing args, invalid flags, nonexistent file, stdin restrictions
- Recursive traversal with multiple directories
- `-Z`/`-z` newline anchor behavior in regex
- `--` end-of-flags in both flag parser and file parser (known limitation — cannot be followed by flags — documented in Known quirks)
- Empty find in all modes (fixed-string, global, regex, in-place)
- Flag ordering (F/R, R/F, Z/z, z/Z) — last-wins per flag pair
- `-r` to stdout (recursive without `-i`)
- `-G` + in-place / in-place-backup
- `-i` combined with `-g`, `-R`, `-E`, and `-g -E`
- Early return when no matches found (`changed.zu == 0`)
- Empty files, empty input, empty replace string
- Long lines and large replacement buffers
- Interactive TUI (via pty): all 7 fields (FIND/RPLC/FLAGS/FILES/INCLUDE/EXCLUDE/BACKUP), `l` flag, include/exclude regex recompile (incl. clear-to-empty and invalid-regex errors), backup suffix, error preview
- `--grep` mode: stdin/file/recursive, `FNAME:` line prefixes, exit codes 0/1/2, `-i`/`-c` conflicts, `-q`, `-` stdin placeholder, binary skip, anchors, empty find
- `-q`/`--quiet` (in-place stderr echo + grep output suppression), `-` stdin placeholder (stdout, grep, and `-c`/`-i`/`-r` conflict errors)
- `-r` error accumulation: unreadable file mid-tree continues traversal, reports `N file(s) failed during processing.`, non-zero exit (2 in grep)
- Unconditional `-c` preview colors (no `isatty` gating)

**Remaining uncovered** (65 lines in the 6 gcov files, mostly OS-level or dead-code paths): signal handler + terminal restore, terminal-width fallbacks (`COLUMNS` env, ioctl failure), preview width-clipping branches, giant-size guards, disk-full, permission-denied, memory allocation failure, signal interrupts during I/O, long backup suffix, stdout write error, temporary file write/close/rename errors, `-c`/`-r` + `-` conflict errors, ftw-failure exit — these require fault injection or special terminal sizes and cannot be exercised in integration tests.

### Bugs found and fixed (31 total)

1. **`jstr_io_writefilefd_len` newline condition inverted** — `jstring/include/io.h:161` in writev path: `(s[sz - 1] == '\n') ? 1 : 0` causes a double `\n` when content already ends with newline (which `process_buffer` always ensures). Fixed to `(s[sz - 1] != '\n') ? 1 : 0` in both `include/io.h` and `build/include/jstr/io.h`. The tool now uses the jstring write functions directly with correct single-trailing-newline output in all modes.

2. **`--include`/`--exclude` matcher never activated during recursion** — `find-and-replace.c:490` checked `G.include_glob` (never set) instead of `m.include_glob`; the matcher was always `NULL`, so include/exclude filtering during `-r` directory traversal was silently broken. Fixed to check `m.include_glob || m.exclude_glob`.

3. **Second pass skip for `--include`/`--exclude` arguments** — `find-and-replace.c:496` used double `ARG_NEXT()` but the for-loop already increments `++i`, causing off-by-one that skipped the next file argument after the flag+glob pair.

4. **`t_edge_special_chars_replace` in `edge-cases.sh` not in TESTS list** — Test function was defined but never executed.

5. **`regex.h` `nmatch` not clipped to `rm[10]`** — `lib/jstring/include/regex.h:711` and build copy passed `nmatch` through without bounds check before `regmatch_t rm[10]` declaration. Added `if (nmatch > 10) nmatch = 10;` in both `include/regex.h` and `build/include/jstr/regex.h`.

6. **`regex.h` `REG_STARTEND` used unconditionally** — `lib/jstring/include/regex.h` used `JSTR_RE_EF_STARTEND` (maps to `REG_STARTEND`) without a fallback; won't compile on musl/BSD. Added `#else` branch with NUL-terminated copy + plain `regexec` fallback in both `include/regex.h` and `build/include/jstr/regex.h`. Affected functions: `jstr_re_exec_len` and `jstr_re_match_len`.

7. **`--` end-of-flags not handled** — `find-and-replace.c` had no handling for bare `--` in either flag parsing or file parsing loops. Added `end_of_flags` flag and `--` detection + skip in both loops. Also allowed `ARG_NEXT()` after `--` to advance past it without processing as a file.

8. **Newline capacity check `>` should be `>=`** — `find-and-replace.c:138` had `buf->capacity > buf->size + 2` which skipped newline appending when buffer had exactly 2 bytes of slack. Fixed to `>=`.

9. **Dead `goto err` after `JSTR_RETURN_ERR`** — `find-and-replace.c` had 3 unreachable `goto err` statements after `JSTR_RETURN_ERR` in the `process_buffer` temp-file write/close/rename error paths. Removed.

10. **Missing `jstr_re_free` in `DO_FREE` block** — `find-and-replace.c:511` freed `buf` but not `G.regex`. Added `jstr_re_free(&G.regex)`.

11. **Empty find in regex mode not guarded** — `process_buffer` called `jstr_re_rplcn_backref_len_exec_j` without checking `find_len == 0`, causing empty regex pattern to match zero-length at position 0 (inconsistent with fixed-string path which returns 0 for empty find). Added `if (find_len == 0) { changed.zu = 0; }` guard in the regex branch.

12. **`file_exists()` used `F_OK | W_OK | R_OK`** — Backup collision check at line 157 used `access(fname, F_OK | W_OK | R_OK)` which incorrectly skipped collision detection for read-only files (access returns -1 when W_OK fails). Fixed to `F_OK` only.

13. **`process_file` regex empty-file skip** — Early-return check `if (file_size < find_len)` skipped regex patterns (like `^$`) that match empty files. Guarded with `!G.regex_use`.

14. **Dead code in file loop** — Unreachable `if (ret != JSTR_RET_SUCC) continue;` at what was line 484, after `xstat` error already caught by `DIE_IF`. Removed.

15. **Misleading "stat() failed" for non-regular files** — File-is-neither-regular-nor-directory case printed "stat() failed" but stat actually succeeded. Changed to "is not a regular file or directory".

16. **NUL bytes in build copy `regex.h`** — Perl codegen turned `\0` escape in source into literal NUL byte in `build/include/jstr/regex.h`, confusing grep/rg (binary file match). Changed `copy[sz] = '\0'` to `copy[sz] = 0` in both source (`include/regex.h:297`) and build copy.

17. **`t_binary_skipped` not in TESTS (same class as #4)** — `tests/run.sh:196` defined `t_binary_skipped` but never listed it, likely because binary detection (`#if 0`) was disabled. Added to TESTS with updated expectation reflecting current no-binary-detection behavior.

26. **Single-character file/dir args treated as the `-` stdin placeholder** — The file-loop check `if (ARG[1] == '\0')` at `main.c:394` never verified `ARG[0] == '-'`, so any one-char argument (`.`, `a`, ...) took the stdin branch: with `-c` it misreported `-c does not work with '-' (stdin).` for a plain `.` directory; in other modes the real file was silently skipped while stdin was read instead. Fixed to `ARG[0] == '-' && ARG[1] == '\0'`. Regression tests `t_single_char_filename`, `t_single_char_confirmed_dir` (the exact `'' 'exp' -r -i -c -g -R .` report) in `tests/files.sh`.

27. **`G.grep_collect` set after file loop — grep TUI never launched** — `G.grep_collect` was assigned at `main.c:608` (after the file-processing loop), so `process_file` never cached files during the loop. By the time `grep_collect` was set, `G.files` was empty and `grep_interactive_loop` had nothing to show. Additionally, `G.interactive_find_buf` was never seeded with `raw_find`, so even if the TUI launched, `grep_rescan` matched against an empty find (matching every line). Fixed by moving the `G.grep_collect` assignment into `parse_long_flag` (when `--grep` is parsed, before any files are processed) and seeding all interactive buffers (`find_buf`, `files_buf`, `include_buf`, `exclude_buf`) before calling `grep_interactive_loop`. Regression test `t_grep_interactive_file_cache` in `tests/grep.sh`.

28. **Grep TUI missing FIND field; controls not pinned; vim mode broken** — Three related grep TUI deficiencies: (a) the grep TUI only had Files/Include/Exclude fields with no FIND field, so the user could not change the find string interactively; (b) controls were not pinned to the bottom of the terminal — they streamed inline after the preview content, so with a short preview the controls floated near the top; (c) `vim_set_insert_mode(1)` was never called, the `[INSERT]`/`[NORMAL]` label was hardcoded to `[INSERT]`, and the cursor positioning did not account for the field index offset. Fixed by adding GREP_FIELD_FIND as field 0, calling `vim_set_insert_mode(1)`, rendering `[INSERT]`/`[NORMAL]` via `vim_is_insert_mode()`, and using `term_move_cursor(start_control_line, 1)` to anchor controls to the bottom. Regression tests `t_grep_interactive_find_field`, `t_grep_interactive_controls_fixed`, `t_grep_interactive_vim_mode` in `tests/grep.sh`.

29. **Confirm TUI scrolling stopped at vis_end — `G.total_lines` capped** — `print_diff_lines` returned early when `G.preview_lines_printed >= vis_end` (the visible window limit), so `G.total_lines = G.preview_lines_printed` was capped at `vis_end`. After scrolling down, `G.selected_line + 1 < G.total_lines` became false too early, preventing further Ctrl-J scrolling. Fixed by changing the three early `return` statements in `print_diff_lines` to set a `render` flag to 0 and continue counting lines without rendering. Regression test `t_confirm_interactive_scroll_past_visend` in `tests/confirm.sh` (20-line file, 15 Ctrl-J presses past old vis_end).

30. **Grep output did not highlight matched strings** — `grep_scan_file` (non-interactive) printed the full matching line without wrapping the matched portion in red, and `grep_print_line` (interactive TUI) did the same. Fixed by computing `match_off`/`match_len` in `grep_collect_file` (using `jstr_strstr_len` for fixed-string, `regmatch_t.rm_so/rm_eo` for regex) and wrapping the match in `COLOR_RED`/`COLOR_RESET` in both `grep_scan_file` and `grep_print_line`. Regression tests `t_grep_match_highlight` and `t_grep_regex_highlight` in `tests/grep.sh`.

### jstring test file added (session 2)

- **`lib/jstring/tests/test-replace-edge.c`** — 8 edge-case tests for `jstr_rplcn_len_from_exec` / `jstr_rplc_len_from_exec`: empty find, empty replace, find>input, multiple replacements (n=3), shorter/longer replacement, overlapping matches, n=0.

### Session 2 additions (8 new tests, 155 deterministic total)

8 new tests added: `t_recursive_empty_dir`, `t_recursive_partial_fail`, `t_dash_filename_no_double_dash`, `t_include_glob_no_match`, `t_long_backup_suffix_collision`, `t_stdin_binary_content`, `t_escape_various_in_replace`, `t_empty_find_stdin_only`. Tests now live in category files under `tests/`.

**Test bugs fixed this session:**
- `t_dash_filename_no_double_dash`: used `-i --` which triggers `end_of_flags` leak (known limitation). Changed to stdin-redirect approach.
- `t_escape_various_in_replace`: used `$()` subshell which strips trailing newlines. Changed to direct file redirect.

## Known quirks

- **Combined flags with `-i`**: `-ir` treats `r` as a backup suffix, not `--recursive`. This is by design — `-i` takes an optional suffix argument, so remaining chars after `i` are consumed as the suffix. Use `-i -r` as separate args.
- **`-G`** was historically broken (set n=0). Now fixed — sets n=1 (single replacement).
- **`--include`/`--exclude`** during recursion was historically broken (matcher never activated). Now fixed.
- **`--exclude`** on command-line files was historically inverted (matching files were processed, non-matching skipped). Now fixed.
- **`--include`/`--exclude` patterns are regexes, not globs**: matched against the
  basename, BRE by default (`-E`/`-I` cflags in effect at parse time apply).
  `--include` on CLI files has no effect — it only applies during directory
  recursion with `-r`. Use `--exclude` for CLI file filtering.
- **`tests/test.c`** is a stale stub with a broken include path; use `tests/run.sh` (unified runner) or individual category files like `tests/basic.sh` instead.
- **`--` end-of-flags**: `find-and-replace foo bar -- file.txt` treats `file.txt` as a filename even if it starts with `-`. This is now fixed — both flag parsing and file parsing loops handle `--`.

  **Known limitation**: `--` cannot be followed by flags like `--include`/`--exclude`. The `end_of_flags` flag set by `--` in the flag loop leaks into the file loop, causing ALL remaining arguments (including flags and their arguments) to be treated as filenames. Flags must be placed before `--`:
  ```
  find-and-replace foo bar -i --include '*.txt' -- dir/   # works
  find-and-replace foo bar -i -- --include '*.txt' dir/   # broken (end_of_flags causes stat errors)
  ```

## Build flags (auto-detected)

`-march=native -Wall -Wextra -Wpedantic` added when cc is gcc or clang.

# Handoff: find-and-replace

## Session 4: `-c` confirm preview rewritten (unified diff → `file:line:` lines)

### What changed

The `-c` dry-run preview prints each removed line as `FNAME:LINE:-<content>`
(red) and each replacement line as `FNAME:LINE:+<content>` (green), combining
the old `file:line:` prefix with the `-`/`+` line markers:

- Every printed line is a `-` or `+` line. The `--- FNAME` / `+++ FNAME` file
  headers and `@@ -START[,COUNT] +START[,COUNT] @@` hunk headers are gone; the
  whole line (prefix included) is colored red for `-` and green for `+`. Colors
  stay unconditional (no `isatty()` gating).
- All matches on the same source line are merged into one block (one old/new
  pair per changed line); unchanged following lines never leak into a block.
- The replacement is assembled once per block into `G.new_buf` (backrefs
  expanded through `G.rplc_buf`), so the `+` side is exactly what the second
  pass writes. `new_buf` is cached in `G` so its allocation is reused across
  blocks and files.

Helpers in `find-and-replace.c`: `match_line_end` (:403), `print_line_prefix`
(:427), `print_diff_lines` (:446). `print_segment`, `print_hunk_range`,
`print_hunk_header`, and the `---`/`+++`/`@@` emission were removed.

### Line-number helpers optimized (incremental counter)

`line_get_start`/`line_get_end` now use `jstr_memrchr`/`memchr` instead of
linear byte loops, and the per-block `line_get_number` byte scan was replaced
with a per-file `line_counter_ty` that counts newlines incrementally over the
monotonic block loop (O(size) total per file, not O(blocks x offset)).
`print_diff_lines` scans with `memchr`; the `len == 0`/`len > 0` tail split
became a single `trailing_nl` branch. Verified identical output on a
10 000-line, 100-block preview. `count_newlines` was removed in favor of
`jstr_countchr_len`.

### Format rules

- The `-` side uses the original file's line numbers; the `+` side numbers the
  **new** file, shifted by the cumulative net change of every previous block
  (`new_shift`), like real diff.
- Line counts follow GNU conventions: a trailing `\n` terminates the last line
  rather than starting a new one; a replacement ending in `\n` (or empty) renders
  an extra empty `+` line only when the block's terminating `\n` survives
  (`trailing_nl`). A fully-deleted region prints an empty `-` line.

### Bugs found & fixed in the rewrite

| # | Bug | Root cause | Fix | File:Line |
|---|---|---|---|---|
| 18 | Preview regex scan didn't strip trailing newline | `process_buffer` removes the final `\n` before running regex (:194-199) but `confirm_scan_file` scanned the full buffer, so `.*` matched an extra empty EOF position (previewed `+worldworld`, engine writes `world`) | Scan region is now `scan_size = size - 1` when the buffer ends in `\n` | `find-and-replace.c:521` |
| 19 | Block overran into the next line when a match consumed its `\n` | `line_get_end(match.end)` extended the block into the following unchanged line (`b\n` delete previewed `-b -c +c`) | `match_line_end` returns `end-1` when `data[end-1] == '\n'`; used in both the grouping condition and `block_end` | `find-and-replace.c:403-409, 597-601` |
| 20 | Old-side line count inflated when block ended in `\n` | Old `count_newlines+1` double-counted a block whose last byte was the consumed terminator | With `match_line_end` the block never ends in its own terminator, so `count_newlines + 1` is exact (empty block = 1 empty line) | `find-and-replace.c:638` |
| 21 | `print_hunk_header` args swapped | `new_line`/`new_count` passed in reverse produced wrong `+` ranges | Passed `(old_line, old_count, new_line, new_count)`; the function was later removed when the format dropped hunk headers | (was line 662) |
| 22 | Every file >1 KiB silently skipped | `jstr_io_isbinary(buf->data, JSTR_MIN(1024, file_size))` passes `sz=1024` while the buffer holds `file_size` bytes, so `strlen(buf) != sz` for any >1024-byte NUL-free file → misclassified as binary → `process_file` returned early | Bound the NUL scan instead of comparing lengths: `memchr(buf->data, '\0', JSTR_MIN(1024, file_size))`. `jstr_io_isbinary` is inherently whole-file (`strlen(buf) != sz`) and cannot express a 1 KiB window. Regression tests `t_large_text_file_processed` (NUL-free >1 KiB processed) and `t_binary_nul_past_kib_processed` (NUL after byte 1024 → still processed) in `tests/io.sh` | `find-and-replace.c:688` |
| 25 | Interactive editor lost files shorter than the initial FIND | `process_file` early-returned `if (file_size < find_len)` for fixed-string finds, so pass 1 never read/cached such files and the editor could not preview or edit them even after shortening FIND | Guard the short-circuit with `!((G.mode & MODE_CONFIRM) && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO))` | `process.c:147` |

### Stale test expectations fixed (pre-existing failures, unrelated to preview)

Confirmed failing on the pre-change binary (jstring behavior drift):

| Test | Was | Now |
|---|---|---|
| `tests/complex.sh` `t_regex_greedy` | `.*`→`X` -g on `a---b---c\n` expected `XX\nX\n` | engine writes `X\n` (whole-string match) |
| `tests/edge-cases.sh` `t_edge_match_empty_lines` | `^$`→`EMPTY` -g on `\n\n` expected 3 EMPTYs | engine writes 2 EMPTYs |
| `tests/confirm.sh` `t_confirm_regex_preview_dot_star_g` | `expected_file` was `worldworld\nworld` | engine writes `world\n` |

### Tests updated for the diff format

`tests/confirm.sh` assertions now grep the `file:line:`-prefixed `-`/`+`
format: `-- '-hello'`/`-- '+hi'` (multiline + backref), `-- '- b'`/`-- '+b'`
(skip_newline), `-- '-hello'`/`-- '+world'` (dot_star_g), and
`grep -c -- '-la la'` == 2 / `+lu lu` == 2 (multi_same_line). No `@@`/`---`
lines are emitted, asserted by negative greps in multiline_regex.

### Files changed

- `find-and-replace.c` — preview rewrite + `scan_size` fix + usage text
- `tests/confirm.sh` — assertions updated to diff format + stale `expected_file`
- `tests/complex.sh`, `tests/edge-cases.sh` — stale expectations
- `QUIRKS.md` §3 — rewritten for the unified-diff preview
- `README.md` — regenerated (`./generate-readme`); `.README.md` install line
  `./build` → `./compile` (no `./build` script exists)

### Verification

- `tests/run.sh`: 11 suites, 0 failed
- `tests/confirm.sh`: 19 passed (14 format tests + 5 line-number tests: `new_shift` across multi-hunk blocks, no-trailing-newline input, empty `-`/`+` lines for deleted regions and line insertions, and a 50-block/5000-line file exercising the incremental `line_counter_ty` and guarding the >1 KiB skip fix)
- `tests/fuzz.sh 60`: 0 crashes
- Hunk headers/line counts manually cross-checked against `diff -u` region-only
  equivalents for: single-line, replacement with embedded `\n`, mid-file /
  last-line / sole-line deletes, no-trailing-newline input, empty-line insertion,
  multi-line find, regex alternation with `-g`, backrefs, and multi-hunk shifts.

## Session 5: line helpers → memchr, incremental counter; >1 KiB skip bug found

- Replaced `line_get_start`/`line_get_end` byte loops with `jstr_memrchr`/
  `memchr`; `line_get_number` (per-block byte scan) with a per-file
  `line_counter_ty` incremental newline counter; simplified `print_diff_lines`
  tail; removed `count_newlines` in favor of `jstr_countchr_len`. Preview output
  byte-identical to Session 4 (verified on a 10 000-line, 100-block file).
- Discovered pre-existing bug #22: every file > 1 KiB was silently skipped
  because `jstr_io_isbinary(buf->data, JSTR_MIN(1024, file_size))` passed
  `sz=1024` while the buffer holds `file_size` bytes (`strlen(buf) != sz` for any
  NUL-free file > 1024 bytes → misclassified binary). Fixed at
  `find-and-replace.c:688` with a length-bounded NUL scan
  (`memchr(buf->data, '\0', JSTR_MIN(1024, file_size))`), regression tests
  `t_large_text_file_processed` and `t_binary_nul_past_kib_processed` in
  `tests/io.sh`. Now 155 deterministic tests.

## Bugs found & fixed (17 total)

### Tool bugs (pre-split `find-and-replace.c`, historical line numbers)

| # | Bug | Root cause | Fix | File:Line |
|---|---|---|---|---|
| 2 | `--include`/`--exclude` matcher never activated during recursion | Checked `G.include_glob` (never set) instead of `m.include_glob` | Changed to `m.include_glob \|\| m.exclude_glob` | `find-and-replace.c:499` |
| 3 | Second-pass skip for `--include`/`--exclude` args | Double `ARG_NEXT()` in file loop (for-loop also `++i`) | Removed one `ARG_NEXT()` | `find-and-replace.c:505-506` |
| 7 | `--` end-of-flags not handled | No `--` detection in either loop | Added `end_of_flags` flag + `--` detection + skip in both loops | `find-and-replace.c:404-421, 475-478` |
| 8 | Newline capacity check off-by-one | `>` instead of `>=` prevented newline append at exact boundary | Changed to `>=` | `find-and-replace.c:142` |
| 9 | Dead `goto err` after `JSTR_RETURN_ERR` | 3 unreachable `goto err` statements after `JSTR_RETURN_ERR` | Removed | `find-and-replace.c:181, 186, 191` |
| 10 | Missing `jstr_re_free` in `DO_FREE` block | Freed `buf` but not `G.regex` | Added `jstr_re_free(&G.regex)` | `find-and-replace.c:520` |
| 11 | Empty find in regex mode not guarded | Called `jstr_re_rplcn_backref_len_exec_j` without checking `find_len == 0` | Added `if (find_len == 0) { changed.zu = 0; }` | `find-and-replace.c:126-128` |
| 12 | `file_exists()` used `F_OK \| W_OK \| R_OK` | `access()` with `W_OK` returns -1 for read-only files → missed collision | Fixed to `F_OK` only | `find-and-replace.c:74` |
| 13 | `process_file` regex empty-file skip | `file_size < find_len` early-return blocked `^$` on empty files | Guarded with `!G.regex_use` | `find-and-replace.c:217` |
| 14 | Dead code in file loop | Unreachable `if (ret != JSTR_RET_SUCC) continue;` after `DIE_IF` | Removed | (was line 484) |
| 15 | Misleading error for non-regular files | "stat() failed" printed when stat actually succeeded | Changed to "is not a regular file or directory" | `find-and-replace.c:502` |

### Test bugs

| # | Bug | Fix | File |
|---|---|---|---|
| 4 | `t_edge_special_chars_replace` defined but never executed | Added to TESTS list | `tests/edge-cases.sh` |
| 17 | `t_binary_skipped` defined but never executed | Added to TESTS list | `tests/run.sh` |

### Library bugs (lib/jstring)

| # | Bug | Fix | File:Line |
|---|---|---|---|
| 1 | `jstr_io_writefilefd_len` newline condition inverted | `(s[sz - 1] == '\n')` → `(s[sz - 1] != '\n')` | `include/io.h:161`, `build/include/jstr/io.h` |
| 5 | `regex.h` `nmatch` not clipped to `rm[10]` | Passed `nmatch` through without bounds check before `regmatch_t rm[10]` | Added `if (nmatch > 10) nmatch = 10;` | `include/regex.h:711`, `build/include/jstr/regex.h` |
| 6 | `regex.h` `REG_STARTEND` used unconditionally | No `REG_STARTEND` fallback for musl/BSD | Added `#else` branch with NUL-terminated copy + plain `regexec` | `include/regex.h`, `build/include/jstr/regex.h` |
| 16 | NUL bytes in build copy `regex.h` | Perl codegen turned `\0` escape into literal NUL byte | `copy[sz] = '\0'` → `copy[sz] = 0` | `include/regex.h:297`, `build/include/jstr/regex.h` |

## Known bugs NOT fixed (blocked by "no code changes" constraint)

| Issue | Description | TODO.md ref |
|---|---|---|
| Binary detection disabled | `#if 0` blocks in `process_file` skip extension/content heuristics | Item 16 |

**Resolved since this table was written:** the `end_of_flags` leak (flag/file
loops merged into one — `-i -- -filename` works) and the regex empty-buffer
short-circuit (regex.h now allows `start_idx == 0` when `*sz == 0`, so `^$`
matches empty files). See Session 8 note.

## Tests added this session (8 new, total 121)

| Test | What it covers |
|---|---|
| `t_recursive_empty_dir` | `-r` on empty directory (exit 0) |
| `t_recursive_partial_fail` | `-r` with one valid + one nonexistent dir (error propagation) |
| `t_dash_filename_no_double_dash` | Dash-prefixed filename via stdin |
| `t_include_glob_no_match` | `--include` with no matching files (no-op) |
| `t_long_backup_suffix_collision` | Backup collision detection |
| `t_stdin_binary_content` | NUL bytes in stdin stream |
| `t_escape_various_in_replace` | `\b\f\r\t\v` in replace string |
| `t_empty_find_stdin_only` | Empty find string in stdin mode |

## jstring test-replace-edge.c (8 edge-case tests)

New file at `lib/jstring/tests/test-replace-edge.c` testing:
- Empty find string
- Empty replace string
- Find longer than input
- Multiple replacements (n=3)
- Shorter replacement (in-place)
- Longer replacement (allocation)
- Overlapping matches (Two-Way, no overlap)
- N=0 (no replacements)

## Remaining uncovered lines (34)All OS-level or dead-code error paths requiring fault injection: disk-full, permission-denied, memory allocation failure, signal interrupts during I/O, long backup suffix, stdout write error, temporary file write/close/rename errors.

## Critical: How to implement the TODO

### Prerequisites
- Set `LD_LIBRARY_PATH=lib/jstring/build/lib` before running the binary
- `./compile` builds; `COVERAGE=1 ./compile` builds with `--coverage`
- Build copy headers at `build/include/jstr/` must stay in sync with `include/`

### Priority order for TODO items

**P0 — both resolved (see Session 8 note):** the `end_of_flags` leak (loops
merged; `-i -- -filename` works) and the regex empty-buffer short-circuit
(`^$` matches empty files since jstring d48000f7/2aaa4c85).

**P1 (correctness):**
1. Integer overflow in `replace.h:1079` (Item 15)
2. `init_defaults()` not idempotent (Item 23)
3. `G.eflags` always zero (Item 50) — add `-e` flag
4. `-r` traversal stops on first error (Item 36)
5. `compile()` recompiles on state change (Item 21, fixed — but flags-after-files is now handled by the per-arg compile calls)

**P2 (test coverage):**
6. `-F` on regex metacharacters `*`/`[` (Item 24 — `.` already covered)
7. `-I` with `-g` (Item 25, done)
8. Escape sequences in REPLACE (Item 26, done)
9. `-r` on empty directory (Item 28, done)
10. `-r` on partially failing dirs (Item 29, done)
11. Dash filename without `--` (Item 30, done)
12. `wait -n` jobserver (Item 27)

**P3 (portability):**
13. Missing `#include <string.h>` / `<unistd.h>` (Item 40)
14. Static link jstring (Item 41)
15. rpath in `./compile` (Item 42)
16. `JSTR_USE_UNLOCKED_IO_READ` portability (Item 44)
17. Sync `build/include/` with `include/` (Item 45)

**P4 (features):**
18. `--version` flag (Item 51, done — Session 8)
19. `-` as stdin placeholder (Item 52)
20. `-q`/`--quiet` (Item 53)
21. Colored diff output (Item 55)

**P5 (cleanup):**
22. `#if 0` blocks (Item 16)
25. Spelling "occurence" → "occurrence" (Item 17)
26. Remove stale `tests/test.c` (Item 18)
27. Document `_j` wrapper convention (Item 20)
28. `argv` strings mutated (Item 22)

### Where to make changes

| File | Location | Purpose |
|---|---|---|
| `main.c` | `main` argument loop | `end_of_flags` (done — single merged loop; flags after `--` are filenames by POSIX design) |
| `process.c` | `process_buffer` | Newline capacity check (`>=` already fixed) |
| `main.c` | `compile` | `compile()` hoisting per-file (Item 21) |
| `main.c` | `init_defaults` | `init_defaults()` idempotency (Item 23) |
| `main.c` | `usage` | Usage string fixes |
| `lib/jstring/include/replace.h` | ~1079 | Integer overflow fix |
| `lib/jstring/include/regex.h` | ~693 | Empty-buffer regex matching |
| Category files in `tests/` | Each file's TESTS list | New tests location |
| `tests/edge-cases.sh` | ~110 | Read-only file + backup test |
| `lib/jstring/tests/test-replace-edge.c` | Full file | jstring edge-case tests |

### Test runner mechanics
- `tests/lib.sh`: shared boilerplate with MAX_JOBS=512 (FAR_MAX_JOBS override) batch-wait jobserver, `/bin/sh` compatible; `run_tests`/`wait_for_results` prints each test name with its PASS/FAIL as it completes
- Each test function: `td=$1`, writes PASS/FAIL to `$td/result`
- Tests registered in TESTS heredoc variable at end of file
- Stderr redirected to `/dev/null` unless error output is tested
- `$PROG` = path to binary (set in `tests/lib.sh`)
- Interactive TUI tests: `tests/pty_drive.py` (mypy-clean) — winsize applied to the pty slave before fork, `--phase`/`--tail` keystrokes, real exit status via non-blocking reap + EIO-safe marker wait

## Session 6: split single file into 4 TUs with `fr_` namespacing

### What changed

`find-and-replace.c` (1068 lines) was deleted and split into a shared header,
three module headers, and 4 translation units that `./compile` builds
**in parallel**:

| File | Contents |
|---|---|
| `common.h` | Includes, macros (`DIE_IF`, `S_LEN`, `R`, MODE_* bits), core types (`mode_ty`, `match_ty`, `matches_ty`, `file_ty`, `files_ty`, `global_ty`), `extern global_ty G` |
| `files.h` | `args_ty`, `matcher_args_ty`, `FILE_CACHE_MAX`/`FILES_CAP_MIN`, `xstat`, `file_exists`, `callback_file`, `matcher`, `file_pushback` |
| `process.h` | `process_buffer`, `process_file` |
| `confirm.h` | Colors/prompt macros, `MATCHES_CAP_MIN`, `confirm_scan_file` |
| `main.c` | `usage`, `compile`, `init_defaults`, `cleanup`, `main`, flag/file parsing; defines `global_ty G` |
| `files.c` | `xstat`, `file_exists`, ftw `callback_file`/`matcher`, `ft_ty` + `#if 0` `exttype` |
| `process.c` | `process_buffer`, `process_file` |
| `confirm.c` | `-c` scan/preview: `confirm_scan_file`, `match_pushback`, `file_pushback`, `line_*`/`line_counter_*`/`match_line_end`, `print_size_t`/`print_line_prefix`/`print_diff_lines` |

### Naming

Functions are grouped by shared namespace prefixes instead of a blanket `fr_`
prefix, so related functions are recognizable at a glance:

- `process_*`: `process_buffer`, `process_file` (replacement engine)
- `confirm_*`: `confirm_scan_file` (-c dry-run scan/preview)
- `match_*`: `match_pushback`, `match_line_end` (match-list helpers)
- `line_*`: `line_get_start`, `line_get_end`, `line_counter_init`,
  `line_counter_get` (line addressing for the preview)
- `print_*`: `print_size_t`, `print_line_prefix`, `print_diff_lines` (preview output)
- `file_*`: `file_exists`, `file_pushback` (filesystem + confirm cache)
- ftw: `callback_file`, `matcher`; stat wrapper: `xstat`
- main: `usage`, `compile`, `init_defaults`, `cleanup`, `main`

Types keep their original names (`mode_ty`, `match_ty`, `files_ty`, ...), as
does the global `global_ty G`. Non-static functions are exactly those called
from another TU (prototypes in `files.h`/`process.h`/`confirm.h`): `xstat`,
`file_exists`, `callback_file`, `matcher`, `file_pushback`, `process_buffer`,
`process_file`, `confirm_scan_file`. Everything else is `static` in its TU.

### Build scripts

- `./compile` now compiles `main.c files.c process.c confirm.c` in
  parallel (`cc -c ... &` + per-pid `wait`, fail on any), then links
  `$OBJS -o find-and-replace`. `COVERAGE=1 COVERAGE_OUTDIR=$TMPDIR` still works
  (objects + `.gcno` land in OUTDIR).
- **`./compile` now passes `-I $DIR/lib/jstring/build/include -L $DIR/lib/jstring/build/lib`**
  so the tool builds against the pinned `lib/jstring` checkout instead of stale
  `/usr/local` copies. This was needed because `/usr/local/include/jstr` was too
  old to declare `jstr_io_isbinary_atleast`; `sudo ./install` in `lib/jstring` is
  now optional.
- `./coverage` runs `gcov` on all 4 sources and aggregates a single summary.
- `./generate-readme` greps `main.c` for the usage string.

### Build gotcha discovered

`lib/jstring/scripts/test` rebuilds `libjstr.so` with `-fsanitize=address`;
linking the tool against it fails on undefined `__asan_*` refs. Re-run
`lib/jstring/./compile` (non-ASan) after any jstring `./test`, before tool builds.

### Tests

- `tests/run.sh` now includes `confirm.sh` (was a 12th suite never wired in):
  **12 suites, 205 deterministic tests**.
- `./test` → 12 suites + 250 fuzz iterations: all green.
- Coverage: **88.8%** of executable lines (up from 86% — confirm preview is now
  exercised in the default run). Remaining uncovered lines are the same
  OS-level/dead-code error paths (disk-full, permission, OOM, temp-file errors,
  `-l` flag, `-h` with single arg, pass-2 re-read when the in-memory cache
  limit is exceeded).
- README regenerated: the `-c` option block now appears (was missing before).

### Not changed

- Binary name is still `find-and-replace`; tests reference only `$PROG`.
- `#if 0` `exttype` block moved verbatim into `files.c`.
- `end_of_flags` leak, regex empty-buffer short-circuit, and binary-detection
  `#if 0` remain known limitations (unchanged).

## Session 7: `--include`/`--exclude` are regexes; confirm TUI gains Include/Exclude/Backup fields

### What changed

`--include`/`--exclude` switched from `fnmatch` globs to POSIX regexes matched
against the file **basename** (BRE by default; `-E`/`-I` cflags in effect at
parse time apply). Compiled objects live in `G.include_re`/`G.exclude_re`,
guarded by `G.have_include`/`G.have_exclude`; raw patterns stay in
`G.include_pat`/`G.exclude_pat`. `fnmatch.h` and `matcher_args_ty` were
removed; the ftw `matcher()` reads `G` directly (args unused) and is selected
as `(G.have_include || G.have_exclude) ? matcher : NULL`.

The `-c` interactive TUI grew from 4 to **7 fields** (FIND, RPLC, FLAGS, FILES,
INCLUDE, EXCLUDE, BACKUP), each an editable buffer:

- INCLUDE/EXCLUDE recompile `G.include_re`/`G.exclude_re` live; empty field
  clears the filter; invalid regex shows a red error like a bad FIND pattern.
- BACKUP sets the in-place backup suffix (`fname + suffix`, same as `-ibak`);
  empty disables backups (`MODE_PRINT_FILE`).
- FLAGS gains `l` (prints each changed filename to stdout,
  `MODE_PRINT_CHANGES`).
- Preview + second pass use the same filter: Files substring + Include/Exclude
  basename regexes (`file_filter_pass` in `main.c`,
  `interactive_file_pass` in `confirm.c` — both compute the basename via
  `jstr_memrchr`, matching the CLI exclude path).
- `max_preview_lines` is `rows - (FIELD_COUNT + 4)` instead of `rows - 9`.
- `vim_handle_key` now takes `field_count` (was hardcoded `% 4`/`% 3`).

`field_ty` enum lives in `confirm.h` (`FIELD_COUNT` must track the buffer order
passed to `confirm_interactive_loop`); helpers `field_buf`/`field_affects_recompile`
keep the loop free of per-field branches.

### Tests

- 5 new regex include/exclude tests in `tests/files.sh`:
  `t_include_regex_suffix` (`\.txt$`), `t_exclude_regex_prefix` (`^i`),
  `t_include_regex_extended` (`-E --include '\.(txt|c)$'`), `t_exclude_regex_cli_files`,
  `t_include_invalid_regex` (invalid pattern → non-zero exit).
- Existing glob tests converted to regex equivalents (e.g. `'*.txt'` →
  `'\.txt$'`, `'i*'` → `'^i'`). `t_include_cli_file_noop` switched to a valid
  regex (`'*.txt'` is now an invalid regex, leading `*`).
- 5 new interactive tests in `tests/confirm.sh`:
  `t_confirm_interactive_include_exclude` (include `\.txt$` + exclude `^b`
  narrow the edit), `t_confirm_interactive_backup` (backup suffix `bak` →
  `fbak`), `t_confirm_interactive_l_flag` (`l` prints the changed path),
  `t_confirm_interactive_clear_filters` (Ctrl-U clears a set Include/Exclude
  filter back to empty), `t_confirm_interactive_invalid_exclude` (invalid
  exclude regex shows `Invalid Exclude regex` error), and
  `t_confirm_interactive_flags_ei` (`E`/`I` flag cases in `parse_interactive_flags`).
- `t_confirm_interactive_error_preview` tab counts updated for 7 fields
  (FLAGS→FIND is 5 tabs now, not 2).
- Full suite: **12 suites, 205 deterministic tests** (files 22→27, confirm
  19→40; flags 14→17, regex 14→16; run.sh shows all 12 green).
- `./coverage` EXIT trap removed `$DIR/$PROG`, deleting the freshly rebuilt
  production binary every run — trap now only removes the temp dir.

### Known subtleties (design)

`--include`/`--exclude` are compiled with the cflags in effect when the flag is
parsed, so `-E --include X` gives an ERE include, while `--include X -E` gives
a BRE include with an ERE find. Same last-wins rule as the other flags.

TUI filter clearing is bounded by the scan-time cache: files excluded by CLI
`--include`/`--exclude` during the `-c` dry-run never enter `G.files`, so
clearing a filter in the interactive editor can only widen the edit set to
files already cached (same as the Files-substring filter). Files excluded at
scan time stay excluded.

## Session 8: backref-over-nsub guardrail verified; flags-between-files segfault fixed; `--version`

### Backreference guardrail

`compile()` (main.c) and `interactive_compile()` (confirm.c) already validated
that every `\1`-`\9` in the replace string is within `re_nsub` of the compiled
find pattern — the CLI path prints an error and exits non-zero (backrefs in the
replace must be double-escaped: `'\\2 \\1'`, because the unescaper turns `\1`
into octal byte 0x01). Confirmed working and added standalone coverage in
`tests/regex.sh` (`t_backref_exceeds_nsub_inplace`, `t_backref_within_nsub_inplace`);
the interactive/non-interactive `-c` paths were already tested in
`tests/confirm.sh`. The library's backref parser is single-digit only and `nmatch`
is clipped to `rm[10]`, so the tool's `\1`-`\9` scan matches the library exactly.

### Bug 23: segfault when flags flip between files

`file1 -R file2` (regex flag after a file) segfaulted (rc=139): `compile()` was
guarded only by `MODE_COMPILED`, so once the first file compiled the Two-Way
matcher, the `-R` parsed later set `MODE_USE_REGEX` but `compile()` was a no-op —
`process_file` then ran `jstr_re_rplcn_backref_len_exec_j` on a never-compiled
`G.regex`. Similarly `-R file1 -F file2` used a stale compiled regex for file2.

Fix: `compile()` now recompiles whenever the matcher-relevant state changes.
Added `G.compiled_regex`/`G.compiled_cflags` to `global_ty` (common.h): the
function stores the mode/cflags it compiled under and re-runs the compile step
(freeing a stale `G.regex` first) if `MODE_USE_REGEX` or `cflags` differ.
`interactive_compile()` (confirm.c) updates the same fields. `n` (`-g`/`-G`)
does not affect compilation, so it is intentionally not part of the snapshot.

Tests: `t_flag_between_files_regex` and `t_flag_between_files_fixed` in
`tests/flags.sh` (TDD: both failed before the fix — the first with rc=139).

### `--version`

`-v`/`--version` prints `find-and-replace 0.1.0` and exits 0. Handled in the
single-arg preamble (alongside `-h`, since `--version` as argv[1] is otherwise
consumed as FIND) and in the flag loop for `prog foo bar --version`. Documented
in the usage string; `t_version` in `tests/flags.sh`.

### Cleanups

- Usage string "occurence" → "occurrence" (TODO item 17).
- `tests/test.c` no longer exists (TODO item 18 was already done).
- Both historical **P0** items are already resolved in the current code:
  the `end_of_flags` leak (flag/file loops were merged into one loop, so
  `-i -- -filename` works) and the regex empty-buffer short-circuit
  (`jstr_re_rplcn_backref_len_from_exec` at regex.h now allows `start_idx == 0`
  when `*sz == 0`, so `^$` matches empty files — from jstring commits d48000f7/
  2aaa4c85, synced to `build/include/jstr/regex.h`). Flags after `--` being
  treated as filenames is correct POSIX behavior, not a bug.

## Session 9: pty driver race fix; confirm.sh fully converted to pty_drive

### Interactive TUI tests: all inline python replaced by `pdrive`

Every remaining inline `python3 -c` block and heredoc `drive.py` script in
`tests/confirm.sh` was converted to the shared `pdrive` wrapper (calls
`tests/pty_drive.py` with `--prog "$PROG" --out "$td/out" --rc "$td/rc"` and an
auto `--ready '-- [INSERT] --'` unless `--noready`/`--ready` is given). Only the
`pdrive` wrapper's `python3` invocation remains in confirm.sh. The 6 broken
converted lines and ~15 inline blocks were fixed (flags_ei, terminal_size_zero
via `--env LINES=`, terminal_cols_env `--env COLUMNS=30`, signal_term
`--signal TERM`, rename_fail via `--after-ready`, invalid_flag_char, no_scroll
via awk, ctrl_d, unknown_escape, control_char, cli_flags, cli_filters_backup,
files_filter, enter_invalid, tiny_terminal `--winsize 1x40`).

### Bug 24: height_capping flake was a pty winsize race, not a layout bug

`t_confirm_interactive_height_capping` (~20% flake in the suite) failed with
"height capping failed. lines=11": the interactive render printed all 5 preview
pairs (10 lines) with no omitted marker and a `\x1b[14;16H` cursor move —
i.e. the first render saw rows≈24 (the parent terminal's size) instead of the
test's `--winsize 12x80`. Root cause: `pty.fork()` spawns the child immediately,
so the child's first render raced pty_drive's post-fork `TIOCSWINSZ` ioctl. Fix
in `tests/pty_drive.py`: `spawn_child()` now creates the pty with
`os.openpty()`, applies the winsize to the **slave before forking**, then forks
with `setsid` + `TIOCSCTTY` + `dup2` + `execvpe`. The race is structurally
impossible now. Verified 10/10 green runs (previously ~20% flake); synthetic
60-concurrent stress harness had 0/480 flakes. `tests/hcsuite.sh` (temp repro
suite) was removed.

### pty_drive.py EIO / early-exit handling

`wait_for_marker` now catches `OSError` (EIO when the child exits before
writing the marker) and returns False; on marker-miss the driver reaps the
child via `os.waitpid(pid, os.WNOHANG)` and writes the **real** exit status to
the rc file, falling back to `"timeout"` only if the child is still running.
mypy clean.

### Runner output: named PASS/FAIL + progressive streaming

- `tests/lib.sh` `report_result` prints each test name with its result as the
  result file appears: `t_foo PASS` / `t_foo FAIL (reason)` / `t_foo FAIL (no result)`.
- `tests/run.sh` runs the 13 suites sequentially, each suite's progressive
  per-test output streaming straight to the terminal (no log capture);
  prints `PASS/FAIL suite` per suite, then
  `=== N suites passed, M failed ===`; exit code mirrors failures. `./test`
  therefore always prints and exits non-zero on any failure.
- `MAX_JOBS` default raised 32 → 512 (`FAR_MAX_JOBS` override, floor 1).
- `t_confirm_interactive_tab_expansion` negative grep fixed: GNU grep treats
  `\t` as stray-`t`, and the post-session non-TUI echo contains a literal tab;
  the check now truncates the TUI region at the `\x1b[?1049l` alt-screen
  teardown and uses `grep -Fq` with a literal tab.

### Verification

- `tests/confirm.sh`: 79/79 (was 40 at Session 7).
- `tests/run.sh`: **13 suites, 265 deterministic tests, 0 failed**; `./test`
  prints full output and exits 0; fuzz 1 iteration 0 crashes.
- `./coverage`: 95.9% lines (1305/1361), 99.2% branches executed, 80.7% taken
  both ways (6 sources: main, files, process, confirm, procfs, vim).
- `tests/pty_drive.py` is mypy-clean.

## Session 10: interactive TUI escaping fixed; controls pinned to the bottom

### Interactive FIND/REPLACE fields now unescape like the CLI

The interactive editor previously seeded its FIND/REPLACE fields from the
**already-unescaped** CLI values and used them **literally** after the loop, so
escape sequences typed in the editor (`\t`, `\n`, octal, ...) never worked the
way they do on the command line. Now:

- `main.c` keeps the raw `argv[1]`/`argv[2]` (captured before the in-place
  `jstr_unescape_p` call) and seeds `G.interactive_find_buf`/`rplc_buf` from
  them; after the interactive loop the buffers are unescaped in place and
  `size` updated (`JSTR_DIFF(jstr_unescape_p(data), data)`).
- `confirm.c` gained `jstr_unescape_copy` (static helper): each redraw builds
  unescaped copies of find/rplc and feeds them to `interactive_compile` and
  `confirm_scan_file`, so the **live preview** and the backref guardrail see
  exactly what the second pass will write. The copies are rebuilt every redraw
  because REPLACE has `affects_recompile = 0`.

New tests in `tests/confirm.sh`: `t_confirm_interactive_escape_find`
(typed `\t` matches a real tab), `t_confirm_interactive_escape_replace`
(typed `\n` inserts a newline), `t_confirm_interactive_escape_live_preview`
(live preview renders the tab match). Note: typing `\t` with the pty driver
requires `--tail '\\t'` (the bare `t` is a vim motion in normal mode).

### Bug 25: interactive editor lost files shorter than the initial FIND

`process_file` early-returned `if (file_size < find_len)` for fixed-string
finds. In the interactive editor the find can still be edited to something
shorter, but the file was never read/cached during pass 1, so it could never
be previewed or edited. The short-circuit now only applies outside the
interactive tty session
(`!((G.mode & MODE_CONFIRM) && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO))`
at `process.c:147`). Uncovered by `t_confirm_interactive_escape_find` (3-byte
file, initial find `hello`); fixed before the pinning work.

### Controls pinned to the bottom of the terminal

The interactive controls block (`-- [INSERT] --` / Stats / 7 fields) used to
stream directly under the preview, so with a short preview it floated near the
top and left the bottom rows blank. Now `confirm_interactive_loop` jumps the
cursor to a fixed bottom anchor before drawing the controls:

- `start_control_line = rows - (FIELD_COUNT + 1)` (row 16 on a 24-row
  screen): `[INSERT]` at `start_control_line`, Stats at `+1`, the 7 fields at
  `+2..+8` so the last field (Backup) ends exactly on the terminal's last row.
- `max_preview_lines` is unchanged (`rows - (FIELD_COUNT + 4)`), so a full
  preview (13 lines) + omitted marker (row 14) always leaves the gap row
  (15) blank and never collides with the pinned header at row 16.
- The explicit blank-separator line and the `preview_lines`/`find_line`
  locals were removed; `active_line = start_control_line + 2 + active_field`.

New test `t_confirm_interactive_controls_fixed` (24x80, short preview: asserts
`\x1b[16;1H` jump + cursor at `\x1b[18;17H`); `t_confirm_interactive_no_scroll`
updated for the new layout (13 preview + omitted marker = 14 newlines before
the first absolute cursor move, then jump to row 16).

### Verification

- `tests/run.sh`: **13 suites, 265 deterministic tests, 0 failed**; confirm
  suite 79/79 across 4 consecutive runs (no pty flakes).
- `./coverage`: 95.9% lines (1305/1361), 99.2% branches executed, 80.7% taken
  both ways.

## Session 11: progressive test output; DO_FREE cleanup; macro-ized magic values

- **Progressive PASS/FAIL**: `tests/lib.sh` `run_tests` now polls result files
  in `wait_for_results` and prints each test's outcome (`report_result`) the
  instant its result file appears, instead of after the whole batch.
  `tests/run.sh` runs the 13 suites sequentially, streaming each suite's output
  straight to the terminal (no per-suite log capture/dump). Verified: PASS
  lines stream (146 at 1s, 257 at 6s of a ~8s full run).
- **`DO_FREE` cleanup pattern**: `#define DO_FREE 0` now lives explicitly in
  `common.h` (was an implicit `#if 0`). Reused-buffer frees that used to sit in
  the confirm TUI (`find_plain`/`rplc_plain` at `done:`) are wrapped in
  `#if DO_FREE` like main.c's `cleanup()`. Regex recompile frees
  (`jstr_re_free` at confirm.c:646/688/703) intentionally stay unwrapped — a
  compiled regex object cannot be reused, so freeing is required before
  recompile.
- **`jstr_unescape_copy` simplified** (`confirm.c`): the manual
  `jstr_reserve_j + memcpy + NUL` became `jstr_assign_len_j(dst, src->data,
  src->size)` (length-explicit; `jstr_assign_j`'s strlen would also work here
  since the interactive buffers are NUL-terminated at `size`).
- **Magic values → macros**: `TERM_ROWS_FALLBACK 24` / `TERM_COLS_FALLBACK 80`
  (terminal-size fallbacks), `FREE_RAM_FALLBACK (1 GiB)` and
  `MEMINFO_BUF_SIZE (4096+1)` (/proc/meminfo), `JSTR_NMATCH_MAX 10`
  (backref capture count, replacing the hardcoded `10`/`rm[10]` across
  common.h/process.c/confirm.c — must stay in sync with jstring's `rm[10]`),
  `BINARY_SCAN_SIZE (JSTR_IO_KIB * 4)` (binary NUL sniffing window).
- **Inline comments added** to the least-commented files: `vim.c` (the whole
  vim-mode editor had none), `procfs.c`, and `confirm.c`'s `setup_terminal`
  raw-mode flag rationale.
- **`md/PLAN-IMPROVE.md`** created with a prioritized improvement list and a
  full design plan for a new **grep mode** (read-only, no replace): semantics,
  exit codes (0/1/2), flag conflicts with `-i`/`-c`, shared match-collection
  extraction from `confirm_scan_file`, and a new `tests/grep.sh` suite.

## Session 12: --grep mode; -q/--quiet; `-` stdin placeholder; -r error accumulation; idempotent init_defaults

Implemented the grep-mode plan from `md/PLAN-IMPROVE.md` (P4 features) plus the
P1 `-r` and `init_defaults` items:

- **`--grep`** (new 14th suite `tests/grep.sh`, 17 tests): read-only, prints
  matching lines to stdout and exits **0** (any match) / **1** (no match) /
  **2** (error). Errors exit 2 via a new `err_exit_code()` helper in `main.c`
  (grep mode picks 2, all other modes keep `EXIT_FAILURE`); applied to regex
  compilation, invalid flag/`--include`/`--exclude`, stat errors, and the
  `-i`/`-c` conflict. Matching is **line-based** (like grep — a regex cannot
  span newlines, unlike the replace path). Lines from named files are
  prefixed `FILE:` (stdin prints bare). Binary files are skipped silently.
  Empty fixed-string find matches every line (grep `''` semantics). New
  `grep_scan_file` lives in `process.c`; `process_file` routes to it right
  after the binary check; stdin (`--grep` with no files, or via `-`) routes
  in `main.c`. Exit code decided at end of `main` via `G.grep_matched`.
- **`-q`/`--quiet`**: suppresses the per-file stderr echo from `-i` and the
  matching-line output in `--grep` (exit codes still returned). Flag loop
  `case 'q'` + `--quiet`.
- **`-` stdin placeholder**: a lone `-` in the FILES list reads stdin at that
  point (`find-and-replace foo bar f1 - f2`). Errors when combined with
  `-i`/`-c`/`-r`. Sets `MODE_HAVE_FILES` so the no-files stdin fallback does
  not double-read. Bare `-` previously fell through the flag loop as a no-op
  (the flag branch now requires `ARG[1] != '\0'`).
- **`-r` error accumulation**: `callback_file` no longer aborts the whole walk
  when one file fails (unreadable, etc.) — it counts into `a.err_count`
  (`args_ty` field) and continues, so later files are still processed. After
  the loop `main` reports `N file(s) failed during processing.` on stderr and
  exits non-zero (2 in grep mode). The `-c` scan pass keeps the strict
  abort-on-error behavior (a partial preview would be unsafe to confirm).
  Tests: `t_recursive_continues_on_error` (files.sh), `t_grep_nonexistent_file`.
- **`init_defaults()` idempotent**: assigns `G.cflags`/`G.n`/`G.eflags`
  instead of `|=`, so repeated calls cannot leak state.
- **Colored diff is default**: confirmed and locked with
  `t_confirm_colored_default` — the `-c` preview colors are unconditional
  (no `isatty` gating); the earlier "gate on tty" idea was dropped by design.

New tests total: files 27→33, flags 23→25, confirm 79→80, + grep suite 17 =
**14 suites, 308 deterministic tests** (2 more in files.sh from the
single-character-arg stdin-placeholder bug fix, bug #26).

## Session 13: bounded -c preview scan; interactive pass-1 only caches files

User report: typing in the FIND field of the `-c -g -r` TUI over the whole
67.6 MB repo (3959 files) pegged the CPU for minutes and the controls never
rendered. Root cause analysis (measured, not guessed):

- The trigger was bug #26's fix letting a single `.` open the TUI over the
  whole tree, but the pathology was pre-existing: `confirm_scan_file` collects
  **every** match (and builds a replacement buffer per block), so with `-g` on
  a large tree each TUI keystroke re-ran a millions-of-matches scan.
- Additionally, pass 1 (`process_file` in confirm mode) *also* ran the full
  unbounded scan and dumped the entire diff to stdout **before** the TUI even
  opened (interactive `-c` printed the preview, then the alt-screen covered
  it). This alone stalled startup with a non-empty find + `-g`.

Two fixes (uncommitted, verified with pty + TDD):

1. **Interactive pass-1 = cache only** (`process.c:217`): when stdin+stdout
   are ttys, pass 1 just `file_pushback`s every file and returns; the TUI scans
   each cached buffer live on every redraw. The non-interactive CLI `-c`
   dry-run still scans + prints everything in pass 1 (unchanged behavior).
2. **Bounded preview scan** (`confirm.c`): `PREVIEW_MATCH_BUDGET_FACTOR 4`;
   `confirm_scan_file` computes `match_budget = max_preview_lines*4` (0 →
   `SIZE_MAX`, so the non-interactive CLI stays unbounded). When `G.matches.size`
   hits the budget it sets `G.preview_full = 1` and stops — in both the regex
   and fixed-string scan loops. Consumers reset `G.preview_full = 0` before
   scanning; the TUI redraw breaks the file loop, shows `N+ matches, M+ files`
   in stats (with a trailing `+`), and prints `... (some previews omitted)`.
   `main.c`'s post-TUI reprint is bounded the same way. Budget covers same-line
   grouping: 4× the display cap (13 lines at 24 rows → 52 matches).

Result: the user's exact command now opens instantly and each keystroke
re-renders in ~tens of ms (whole flow measured 0.38 s under the pty, including
the bounded scan of all cached files on every redraw).

Tests (TDD, red verified by re-introducing both bugs): `t_confirm_interactive_preview_truncated`
(100-line file > 52-match budget; asserts `+ matches` stats suffix and the
omitted marker, exercising both fixed-string and regex scan paths) and
`t_confirm_interactive_no_pre_tui_dump` (asserts no preview line precedes the
alt-screen enter `\x1b[?1049h`, byte-ordered via awk `index()`). confirm 80→82→86,
total **308**.

## Test-Driven Development (TDD) Guidelines

For every new feature, bug fix, or behavioral change introduced to the codebase:
- Always write a corresponding, robust failing integration test first under `tests/` before implementing the fix/change.
- Verify that the test fails as expected.
- Implement the code change, compile, and run the test suite to ensure the new test passes and no regressions are introduced.
- Maintain comprehensive coverage of edge cases and input variations.
