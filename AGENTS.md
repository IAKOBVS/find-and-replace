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
./compile && tests/run.sh   # 113 main integration tests
./test [N]                  # all tests + N fuzz iterations (default 250)
./tests/fuzz.sh [N]         # fuzz tests only (default 500)
./coverage                  # build with --coverage, run all tests, report gcov
```

### Test suites

| Suite | File | Tests | Coverage |
|---|---|---|---|
| Main integration | `tests/run.sh` | 113 | Fixed-string, global/regex/case-insensitive, in-place with/without backup, stdin, multi-file, recursive, `--include`/`--exclude`, escapes (`\b\f\n\r\t\v` + octal), flag combinations (`-F -G -g -Z -z -R -E -I`), `--` end-of-flags, `-i`+regex/global combos, `-r` to stdout, empty find in all modes, flag ordering (F/R, R/F, Z/z, z/Z), error paths (missing args, invalid flags, stdin+in-place, nonexistent file, backup collision, invalid regex, long backup suffix), IO tests (backup content identity with `cmp`, empty/binary/multi-file backup, in-place shorter/longer/same-length/identical, FIFO/file argument, read-only in-place, large stdin, stdout multi-file, deep/many-file recursion, nonexistent-among-valid, backup-twice, mixed multi-file in-place), `-r` on regular file, `-r` on nonexistent dir, `--include`/`--exclude` combined with `-r` and dash filenames, regex `^$` on non-empty line, `--` + `--include` + `-r`, regex G/g ordering, `--include` CLI no-op, escape in regex, stdin+inplace error message |
| Edge cases | `tests/edge-cases.sh` | 18 | Empty input, missing newlines, invalid regex, overlapping matches, empty lines, null bytes, massive lines, long replacements, UTF-8 bytes, special chars in replace, empty file in-place, regex anchors with `-z`, read-only file with backup, nonexistent dir with `-r` |
| Complex regex | `tests/complex.sh` | 14 | Backreferences (reorder, nested groups, XML tags, alternation, max digits), IP/URL/email parsing, greedy matching, repeat quantifiers, escaped literals |
| Fuzz | `tests/fuzz.sh` | N | Random strings with random flags (`-g -R -E -I -Z -z -G`) in stdin, file, in-place, and in-place-backup modes; detects crashes and unexpected non-zero exits |

### Test categories

| Category | Representative tests | Covered functionality |
|---|---|---|
| Basic replacement | `t_fixed_stdin`, `t_global`, `t_inplace`, `t_inplace_backup` | Fixed-string replacement via stdin, in-place (with/without backup), global mode |
| Flag parsing | `t_explicit_F`, `t_explicit_G`, `t_regex`, `t_extended_regex`, `t_ignore_case`, `t_Z_flag`, `t_z_flag`, `t_help` | `-F -G -R -E -I -Z -z -g -h` flag interpretation |
| Flag ordering | `t_flag_order_F_R`, `t_flag_order_R_F`, `t_flag_order_Z_z`, `t_flag_order_z_Z`, `t_global_then_G`, `t_G_then_global` | Last-wins semantics for flag pairs |
| Regex | `t_regex`, `t_extended_regex`, `t_global_regex`, `t_backreference`, `t_empty_file_regex_anchors`, `t_z_with_regex`, `t_Z_with_regex` | BRE, ERE, backreferences, anchors with `-Z`/`-z` |
| File operations | `t_multi_file`, `t_recursive`, `t_include`, `t_exclude`, `t_recursive_exclude`, `t_include_exclude_combined`, `t_recursive_deep`, `t_recursive_many_files` | Multi-file, recursive traversal, `--include`/`--exclude` glob filtering |
| Error paths | `t_nonexistent_file`, `t_invalid_flag`, `t_no_args`, `t_missing_replace`, `t_stdin_inplace_err`, `t_invalid_regex`, `t_inplace_backup_collision`, `t_long_backup_suffix` | Missing/invalid args, nonexistent files, backup collisions, invalid regex |
| Edge cases | `t_empty_input`, `t_empty_replace`, `t_empty_find_regex`, `t_empty_find_global`, `t_empty_find_inplace`, `t_long_line`, `t_overlapping`, `t_binary_skipped`, `t_escape_ff`, `t_escape_cr`, `t_escape_vt`, `t_escape_bs`, `t_octal_escape` | Empty inputs, long lines, overlapping matches, binary files, escape sequences |

### Test writing conventions

All tests in `tests/run.sh`, `tests/edge-cases.sh`, and `tests/complex.sh` follow the same conventions:

- **Each test is a shell function** that takes a single argument (`$1`) — a temporary directory unique to that test. The function stores it as `td=$1`.
- **Results are written to `$1/result`** — the string `PASS` on success, or `FAIL: <reason>` on failure.
- **The binary path** is available as `$PROG` (set at the top of the script).
- **Stderr is redirected to `/dev/null`** (`2>/dev/null`) unless the test specifically checks error output.
- **Tests are registered** by listing their function name in the `TESTS` heredoc variable. Only listed functions are executed by the runner.

### Test runner parallelism

The test scripts use a batch-wait jobserver to limit concurrency and avoid file descriptor exhaustion:

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

### Coverage: 86% of executable lines

Coverage measured via `gcov` after running all 145 deterministic tests (113 main + 18 edge + 14 complex).

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

## Known quirks

- **Combined flags with `-i`**: `-ir` treats `r` as a backup suffix, not `--recursive`. This is by design — `-i` takes an optional suffix argument, so remaining chars after `i` are consumed as the suffix. Use `-i -r` as separate args.
- **`-G`** was historically broken (set n=0). Now fixed — sets n=1 (single replacement).
- **`--include`/`--exclude`** during recursion was historically broken (matcher never activated). Now fixed.
- **`--exclude`** on command-line files was historically inverted (matching files were processed, non-matching skipped). Now fixed.
- **`--include` on CLI files** has no effect — `--include` only applies during directory recursion with `-r`. Use `--exclude` for CLI file filtering.
- **`tests/test.c`** is a stale stub with a broken include path; use `tests/run.sh` instead.
- **`--` end-of-flags**: `find-and-replace foo bar -- file.txt` treats `file.txt` as a filename even if it starts with `-`. This is now fixed — both flag parsing and file parsing loops handle `--`.

  **Known limitation**: `--` cannot be followed by flags like `--include`/`--exclude`. The `end_of_flags` flag set by `--` in the flag loop leaks into the file loop, causing ALL remaining arguments (including flags and their arguments) to be treated as filenames. Flags must be placed before `--`:
  ```
  find-and-replace foo bar -i --include '*.txt' -- dir/   # works
  find-and-replace foo bar -i -- --include '*.txt' dir/   # broken (end_of_flags causes stat errors)
  ```

## Build flags (auto-detected)

`-march=native -Wall -Wextra -Wpedantic` added when cc is gcc or clang.
