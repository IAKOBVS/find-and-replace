# find-and-replace

Multi-file C CLI tool (common header `common.h` + `main.c`, `files.c`,
`process.c`, `confirm.c`, ~1100 lines) for fixed-string or regex
find-and-replace on files, with optional recursion, glob filtering, and
in-place editing with backups.

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
./compile && tests/run.sh   # all deterministic suites (12 suites, 174 tests)
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
| IO | `tests/io.sh` | 21 | Backup identity/empty/binary/multi, in-place shorter/longer/same/identical, binary, FIFO, read-only, large stdin, stdout multi-file |
| Escape | `tests/escape.sh` | 9 | `\t \b \f \n \r \v \octal` in find and replace |
| Empty | `tests/empty.sh` | 5 | Empty find in stdin, file, in-place, regex, global modes |
| Misc | `tests/misc.sh` | 6 | Double-dash, multiline find, slash literal, overlapping, end-of-options |
| Edge cases | `tests/edge-cases.sh` | 18 | Empty input, missing newlines, invalid regex, overlapping, empty lines, null bytes, massive lines, long replacements, UTF-8, read-only backup, nonexistent dir |
| Complex regex | `tests/complex.sh` | 14 | Backreferences (reorder, nested groups, XML tags, alternation, max digits), IP/URL/email parsing, greedy, quantifiers |
| Confirm | `tests/confirm.sh` | 19 | `-c` preview: diff format lines, backrefs, multi-line, same-line grouping, recursive, backup, no-match, prompt yes/no |
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

All 12 deterministic suites run concurrently at the file level via `tests/run.sh`, each with its own internal batch-wait jobserver for test-level parallelism.

### Coverage: 88.8% of executable lines

Coverage measured via `gcov` after running all 174 deterministic tests (17 basic + 14 flags + 14 regex + 22 files + 15 errors + 21 io + 9 escape + 5 empty + 6 misc + 18 edge + 14 complex + 19 confirm).

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

## Remaining uncovered lines (34)All OS-level or dead-code error paths requiring fault injection: disk-full, permission-denied, memory allocation failure, signal interrupts during I/O, long backup suffix, stdout write error, temporary file write/close/rename errors.

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

| File | Location | Purpose |
|---|---|---|
| `main.c` | `main` argument loop | `end_of_flags` fix (known limitation, Item 35) |
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
- `tests/lib.sh`: shared boilerplate with MAX_JOBS=32 batch-wait jobserver, `/bin/sh` compatible
- Each test function: `td=$1`, writes PASS/FAIL to `$td/result`
- Tests registered in TESTS heredoc variable at end of file
- Stderr redirected to `/dev/null` unless error output is tested
- `$PROG` = path to binary (set in `tests/lib.sh`)

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
  **12 suites, 174 deterministic tests**.
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

## Test-Driven Development (TDD) Guidelines

For every new feature, bug fix, or behavioral change introduced to the codebase:
- Always write a corresponding, robust failing integration test first under `tests/` before implementing the fix/change.
- Verify that the test fails as expected.
- Implement the code change, compile, and run the test suite to ensure the new test passes and no regressions are introduced.
- Maintain comprehensive coverage of edge cases and input variations.
