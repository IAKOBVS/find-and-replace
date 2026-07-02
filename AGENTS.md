# find-and-replace

Single-file C CLI tool (`find-and-replace.c`, ~480 lines) for fixed-string or regex find-and-replace on files, with optional recursion, glob filtering, and in-place editing with backups.

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
./compile && tests/run.sh   # 87 integration tests (57 main + 16 edge + 14 complex)
./test [N]                  # all tests + N fuzz iterations (default 250)
./tests/fuzz.sh [N]         # fuzz tests only (default 500)
./coverage                  # build with --coverage, run all tests, report gcov
```

### Test suites

| Suite | File | Tests | Coverage |
|---|---|---|---|
| Main integration | `tests/run.sh` | 57 | Fixed-string, global/regex/case-insensitive, in-place with/without backup, stdin, multi-file, recursive, `--include`/`--exclude`, escapes (`\b\f\n\r\t\v` + octal), flag combinations (`-F -G -g -Z -z -R -E -I`), error paths (missing args, invalid flags, stdin+in-place, nonexistent file, backup collision) |
| Edge cases | `tests/edge-cases.sh` | 16 | Empty input, missing newlines, invalid regex, overlapping matches, empty lines, null bytes, massive lines, long replacements, UTF-8 bytes, special chars in replace, empty file in-place, regex anchors with `-z` |
| Complex regex | `tests/complex.sh` | 14 | Backreferences (reorder, nested groups, XML tags, alternation, max digits), IP/URL/email parsing, greedy matching, repeat quantifiers, escaped literals |
| Fuzz | `tests/fuzz.sh` | N | Random strings with random flags (`-g -R -E -I -Z -z -G`) in stdin, file, in-place, and in-place-backup modes; detects crashes and unexpected non-zero exits |

### Coverage: 84% of executable lines

Coverage measured via `gcov` after running all deterministic tests.

**Covered paths include:**
- All flag parsing (`-F -G -g -R -E -I -Z -z -r -h`)
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
- Early return when no matches found (`changed.zu == 0`)
- Empty files, empty input, empty replace string
- Long lines and large replacement buffers

**Remaining uncovered** (35 lines, all OS-level error paths): disk-full, permission-denied, memory allocation failure, signal interrupts during I/O — these require fault injection and cannot be exercised in integration tests.

### Bugs found and fixed during test improvements

1. **`--include`/`--exclude` matcher never activated during recursion** — `find-and-replace.c:490` checked `G.include_glob` (never set) instead of `m.include_glob`; the matcher was always `NULL`, so include/exclude filtering during `-r` directory traversal was silently broken. Fixed to check `m.include_glob || m.exclude_glob`.

2. **Second pass skip for `--include`/`--exclude` arguments** — `find-and-replace.c:496` used double `ARG_NEXT()` but the for-loop already increments `++i`, causing off-by-one that skipped the next file argument after the flag+glob pair.

3. **`t_edge_special_chars_replace` in `edge-cases.sh` not in TESTS list** — Test function was defined but never executed.

## Known quirks

- **Combined flags with `-i`**: `-ir` treats `r` as a backup suffix, not `--recursive`. This is by design — `-i` takes an optional suffix argument, so remaining chars after `i` are consumed as the suffix. Use `-i -r` as separate args.
- **`-G`** was historically broken (set n=0). Now fixed — sets n=1 (single replacement).
- **`--include`/`--exclude`** during recursion was historically broken (matcher never activated). Now fixed.
- **`--exclude`** on command-line files was historically inverted (matching files were processed, non-matching skipped). Now fixed.
- **`--include` on CLI files** has no effect — `--include` only applies during directory recursion with `-r`. Use `--exclude` for CLI file filtering.
- **`tests/test.c`** is a stale stub with a broken include path; use `tests/run.sh` instead.

## Build flags (auto-detected)

`-march=native -Wall -Wextra -Wpedantic` added when cc is gcc or clang.
