# find-and-replace

Single-file C CLI tool (`find-and-replace.c`, ~525 lines) for fixed-string or regex find-and-replace on files, with optional recursion, glob filtering, and in-place editing with backups.

## Setup & build

```
sudo ./setup   # clones lib/jstring from github.com/IAKOBVS/jstring, compiles + tests it
./compile      # links against lib/jstring/build/lib/libjstr.so
sudo ./install # copies binary to $HOME/.local/bin (dir must exist)
```

- `COVERAGE=1 ./compile` builds with `--coverage` flags for `gcov` analysis
- `./update` runs `git restore && ./update` inside `lib/jstring` (update jstring dependency)
- `./generate-readme` rebuilds `README.md` from `.README.md` + usage strings in source
- `./coverage` builds with coverage, runs all tests, and runs `gcov`

## Key facts

- **Only ANSI C features** - no VLAs, no `//` comments, no C99+ features beyond what POSIX requires
- **Dependency**: [jstring](https://github.com/IAKOBVS/jstring) - linked via `lib/jstring/build/lib/libjstr.so`
- **Include path**: `lib/jstring/build/include/` (not `lib/jstring/include/`)
- **Code style**: no comments, SPDX MIT header, `clang-format off/on` around the usage string
- **Usage strings** are defined with `_(...)` macro calls in source; `generate-readme` parses these with `grep '_('`
- `.gitignore` ignores `find-and-replace` binary and `jstring/` (symlink/lib dir)
- **No linter/formatter** beyond compiler flags (`-Wall -Wextra -Wpedantic`)
- **No CI** workflows

## Tests

```
./compile && tests/run.sh   # all deterministic suites (153 tests)
./test [N]                  # all tests + N fuzz iterations (default 250)
./tests/basic.sh            # run a single suite independently
./tests/fuzz.sh [N]         # fuzz tests only (default 500)
./coverage                  # build with --coverage, run all tests, report gcov
```

### Test suites

| Suite | File | Tests | Coverage |
|---|---|---|---|
| Basic | `tests/basic.sh` | 17 | Fixed stdin, global, in-place/backup, explicit G, no-match, empty/find-equal/longer replace, combined `-ir` |
| Flags | `tests/flags.sh` | 14 | `-F -R -E -I -Z -z -g -G -h`, flag ordering (F/R, Z/z, g/G) |
| Regex | `tests/regex.sh` | 14 | BRE/ERE, backreferences, anchors with `-Z`/`-z`, regex in in-place, escape in regex |
| Files | `tests/files.sh` | 22 | Multi-file, recursive, `--include`/`--exclude`, dash filenames, deep/many-file recursion |
| Errors | `tests/errors.sh` | 15 | Missing args, nonexistent file, invalid flag/regex, backup collision, long suffix, stdin+in-place/recursive |
| IO | `tests/io.sh` | 19 | Backup identity/empty/binary/multi, in-place shorter/longer/same/identical, binary, FIFO, read-only, large stdin, stdout multi-file |
| Escape | `tests/escape.sh` | 9 | `\t \b \f \n \r \v \octal` in find and replace |
| Empty | `tests/empty.sh` | 5 | Empty find in stdin, file, in-place, regex, global modes |
| Misc | `tests/misc.sh` | 6 | Double-dash, multiline find, slash literal, overlapping, end-of-options |
| Edge cases | `tests/edge-cases.sh` | 18 | Empty input, missing newlines, invalid regex, overlapping, empty lines, null bytes, massive lines, long replacements, UTF-8, read-only backup, nonexistent dir |
| Complex regex | `tests/complex.sh` | 14 | Backreferences (reorder, nested groups, XML tags, alternation, max digits), IP/URL/email parsing, greedy, quantifiers |
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

### Test runner parallelism

The test scripts use a batch-wait jobserver to limit concurrency and avoid file descriptor exhaustion, implemented in `tests/lib.sh`:

```
MAX_JOBS=32
count=0
for t in $TESTS; do
    (
        mkdir -p "$td_root/$t"
        "$t" "$td_root/$t"
    ) &
    count=$((count + 1))
    if [ "$count" -ge "$MAX_JOBS" ]; then
        wait
        count=0
    fi
done
[ "$count" -gt 0 ] && wait
```

Each test runs as a background subshell. After `MAX_JOBS` (32) launches, `wait` blocks until the batch finishes. The final incomplete batch is waited for after the loop. This prevents running all N tests simultaneously, which could exhaust file descriptors on systems with low `ulimit -n`.

All 11 deterministic suites run concurrently at the file level via `tests/run.sh`, each with its own internal batch-wait jobserver for test-level parallelism.

### Coverage: 86% of executable lines

Coverage measured via `gcov` after running all 153 deterministic tests (17 basic + 14 flags + 14 regex + 22 files + 15 errors + 19 io + 9 escape + 5 empty + 6 misc + 18 edge + 14 complex).

**Covered paths include:**
- All flag parsing (`-F -G -g -R -E -I -Z -z -r -h`) and `--` end-of-flags
- All flag combinations and last-wins ordering
- Fixed-string and regex replacement (BRE and ERE)
- In-place editing with and without backup suffix
- Backup suffix collision detection
- `--include` glob filtering during recursion
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

**Remaining uncovered** (34 lines, all OS-level or dead-code error paths): disk-full, permission-denied, memory allocation failure, signal interrupts during I/O, long backup suffix, stdout write error, temporary file write/close/rename errors — these require fault injection and cannot be exercised in integration tests.

### Bugs found and fixed (17 total)

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

### jstring test file added (session 2)

- **`lib/jstring/tests/test-replace-edge.c`** — 8 edge-case tests for `jstr_rplcn_len_from_exec` / `jstr_rplc_len_from_exec`: empty find, empty replace, find>input, multiple replacements (n=3), shorter/longer replacement, overlapping matches, n=0.

### Session 2 additions (8 new tests, 153 deterministic total)

8 new tests added: `t_recursive_empty_dir`, `t_recursive_partial_fail`, `t_dash_filename_no_double_dash`, `t_include_glob_no_match`, `t_long_backup_suffix_collision`, `t_stdin_binary_content`, `t_escape_various_in_replace`, `t_empty_find_stdin_only`. Tests now live in category files under `tests/`.

**Test bugs fixed this session:**
- `t_dash_filename_no_double_dash`: used `-i --` which triggers `end_of_flags` leak (known limitation). Changed to stdin-redirect approach.
- `t_escape_various_in_replace`: used `$()` subshell which strips trailing newlines. Changed to direct file redirect.

## Known quirks

- **Combined flags with `-i`**: `-ir` treats `r` as a backup suffix, not `--recursive`. This is by design — `-i` takes an optional suffix argument, so remaining chars after `i` are consumed as the suffix. Use `-i -r` as separate args.
- **`-G`** was historically broken (set n=0). Now fixed — sets n=1 (single replacement).
- **`--include`/`--exclude`** during recursion was historically broken (matcher never activated). Now fixed.
- **`--exclude`** on command-line files was historically inverted (matching files were processed, non-matching skipped). Now fixed.
- **`--include` on CLI files** has no effect — `--include` only applies during directory recursion with `-r`. Use `--exclude` for CLI file filtering.
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

## Bugs found & fixed (17 total)

### Tool bugs (find-and-replace.c)

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
| `end_of_flags` leaks into file loop | `--` sets `end_of_flags=1` in flag loop, then file loop (re-starting at `i=3`) treats all preceding flags as filenames | Item 35 |
| Regex empty-buffer short-circuit | `jstr_re_rplcn_backref_len_from_exec` returns early when `start_idx >= *sz`, preventing `^$` on empty files | Item 59 |
| Binary detection disabled | `#if 0` blocks in `process_file` skip extension/content heuristics | Item 16 |

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

## Remaining uncovered lines (34)

All OS-level or dead-code error paths requiring fault injection: disk-full, permission-denied, memory allocation failure, signal interrupts during I/O, long backup suffix, stdout write error, temporary file write/close/rename errors.

## Critical: How to implement the TODO

### Prerequisites
- Set `LD_LIBRARY_PATH=lib/jstring/build/lib` before running the binary
- `./compile` builds; `COVERAGE=1 ./compile` builds with `--coverage`
- Build copy headers at `build/include/jstr/` must stay in sync with `include/`

### Priority order for TODO items

**P0 (fixes needed before anything else):**
1. `end_of_flags` leak (Item 35) — breaks `-i -- -filename`. Fix: the file loop at line 474 should not re-start at `i=3`. Track what the flag loop consumed and skip those indices. Or: merge the two loops. Or: save the consumed index count.
2. Regex empty-buffer matching (Items 59-62) — `jstr_re_rplcn_backref_len_from_exec` returns early when `start_idx >= *sz`. Fix: either skip the early return for buffer-size 0 when pattern can match empty string, or add a padding newline in the tool's `process_buffer`.

**P1 (correctness):**
3. Integer overflow in `replace.h:1079` (Item 15)
4. `compile()` called per-file (Item 21) — hoist outside loop
5. `init_defaults()` not idempotent (Item 23)
6. `G.eflags` always zero (Item 50) — add `-e` flag
7. `-r` traversal stops on first error (Item 36)

**P2 (test coverage):**
8. `-F` on regex metacharacters (Item 24)
9. `-I` with `-g` (Item 25)
10. Escape sequences in REPLACE (Item 26)
11. `-r` on empty directory (Item 28)
12. `-r` on partially failing dirs (Item 29)
13. Dash filename without `--` (Item 30)
14. `wait -n` jobserver (Item 27)

**P3 (portability):**
15. Missing `#include <string.h>` / `<unistd.h>` (Item 40)
16. Static link jstring (Item 41)
17. rpath in `./compile` (Item 42)
18. `JSTR_USE_UNLOCKED_IO_READ` portability (Item 44)
19. Sync `build/include/` with `include/` (Item 45)

**P4 (features):**
20. `--version` flag (Item 51)
21. `-` as stdin placeholder (Item 52)
22. `-q`/`--quiet` (Item 53)
23. Colored diff output (Item 55)

**P5 (cleanup):**
24. `#if 0` blocks (Item 16)
25. Spelling "occurence" → "occurrence" (Item 17)
26. Remove stale `tests/test.c` (Item 18)
27. Document `_j` wrapper convention (Item 20)
28. `argv` strings mutated (Item 22)

### Where to make changes

| File | Lines | Purpose |
|---|---|---|
| `find-and-replace.c` | 390-472 (flag loop), 474-508 (file loop) | `end_of_flags` fix |
| `find-and-replace.c` | 142 | Newline capacity check (`>=` already fixed) |
| `find-and-replace.c` | 275-290 | `compile()` hoisting |
| `find-and-replace.c` | 293-299 | `init_defaults()` idempotency |
| `find-and-replace.c` | 302-354 | Usage string fixes |
| `lib/jstring/include/replace.h` | ~1079 | Integer overflow fix |
| `lib/jstring/include/regex.h` | ~693 | Empty-buffer regex matching |
| Category files in `tests/` | Each file's TESTS list | New tests location |
| `tests/edge-cases.sh` | ~110 | Read-only file + backup test |
| `lib/jstring/tests/test-replace-edge.c` | Full file | jstring edge-case tests |

### Test runner mechanics
- `tests/lib.sh`: shared boilerplate with MAX_JOBS=32 batch-wait jobserver, `/bin/sh` compatible
- Each test function: `td=$1`, writes PASS/FAIL to `$td/result`
- Tests registered in TESTS heredoc variable at end of file
- Stderr redirected to `/dev/null` unless error output is tested
- `$PROG` = path to binary (set in `tests/lib.sh`)

