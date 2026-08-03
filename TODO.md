# TODO: potential improvements

## ✅ Recently fixed

- **NUL bytes in build copy `regex.h`** — `copy[sz] = '\0'` → `copy[sz] = 0` in both source and build copies.
- **Dead code in file loop** — Unreachable `if (ret != JSTR_RET_SUCC) continue;` removed.
- **Misleading error on non-regular file** — "stat() failed" changed to "is not a regular file or directory".
- **`file_exists()` uses `F_OK` only** — Backup collision check no longer requires `W_OK`, fixing detection for read-only files.
- **Regex empty-file skip guarded** — `process_file` now skips size check when `G.regex_use` is set, allowing `^$` to match empty files.
- **FD exhaustion mitigated** — `tests/lib.sh` provides MAX_JOBS=32 batch-wait jobserver used by all category files to limit concurrent subshells.
- **New tests added** — `--` + `--include` + `-r`, `-r` on regular file, long backup suffix, invalid regex, stdin+`-i` error path.

## Infrastructure

- **Integer overflow in `replace.h:1079`** — `new_size = *sz + changed * (rplc_len - find_len)` in `jstr_rplcn_len_from_exec` can overflow `size_t` when `changed * (rplc_len - find_len)` exceeds `SIZE_MAX - *sz`. With global mode (`-g`) on a large file, this could silently corrupt. Fix with saturation check or early return.
- **`#if 0` blocks for binary detection** — `find-and-replace.c:219-223,230-234` have disabled binary file detection via `exttype()`. Clean up or remove the dead code.
- **Spelling in usage string** — Line 308: "occurence" should be "occurrence". Fix in `_(...)` macro.
- **Remove stale `tests/test.c`** — Stub with broken include path; use `tests/run.sh` (unified runner) or category files in `tests/` instead.
- **Microbenchmark suite** — Basic performance tests for large files, many replacements, long lines, regex vs fixed-string throughput.
- **Document `_j` wrapper convention** in AGENTS.md — Functions with `_j` suffix take `jstr_ty *` instead of `char **s, *sz, *cap`.
- **`compile()` called per-file** — `find-and-replace.c:483` calls `compile()` for every file in the file loop. Though `compile()` is a no-op after the first call, it's wasteful. Hoist outside the loop.
- **`argv` strings mutated** — `jstr_unescape_p` modifies `FIND`/`RPLC` in-place. The mutated argv is visible in `ps` output. Minor cosmetic issue.
- **`init_defaults()` not idempotent** — `G.cflags |= JSTR_RE_CF_NEWLINE` is an OR, so calling twice is fine. But other fields (`n`, `eflags`, `recursive`) are not reset. If called again (currently it isn't), stale state leaks.
- **Add test for `-F` on regex metacharacters (`.`, `*`, `[`)** — Verify fixed-string mode correctly treats regex metacharacters as literals.
- **Add test for `-I` with `-g` (global ignore case)** — Combined case-insensitive and global replacement.
- **Add test for escape sequences in REPLACE string** — Verify `\n`, `\t`, `\r` etc. work in the replacement string.
- **Use `wait -n` for better jobserver throughput** — `wait -n` (bash 4.3+) returns as soon as any background job completes, allowing the next test to start immediately rather than waiting for the full batch of 32 to finish. Currently blocked by `/bin/sh` shebang (POSIX `wait` only waits for all).
- **Test for `-r` on empty directory** — Recursive mode on an empty directory should succeed (no files to process, exit 0).
- **Test for `-r` on partially failing directories** — Recursive traversal where `process_file` fails on some files (e.g., permission denied) — verify error propagation vs continuation.
- **Test for dash filename without `--`** — A file literally named `-foo` should be treated as a filename after `--`, and the error/warning behavior without `--` should be tested.
- **Investigate: does `--include` pattern negation work?** — e.g., `--include '!*.txt'`. The glob matcher may or may not support `!` prefix for exclusion. Document or add support.

## Error handling

- **`end_of_flags` leaks from flag loop into file loop** — When `--` is encountered in the flag loop, `end_of_flags` is set to 1. The file loop's guard `end_of_flags || *ARG != '-'` then causes ALL remaining arguments (including `-i`, `-r`, `--include`, `--exclude`, and their arguments) to be treated as filenames rather than being skipped. This means `--` cannot be followed by flags like `--include` — the flags must come BEFORE `--`. The file loop at line 479 should handle known flags before checking `end_of_flags`.
- **`-r` traversal stops on first error** — If `process_file` fails during recursive traversal (e.g., permission denied), `jstr_io_ftw` propagates the error and the entire operation stops. Consider error accumulation (continue processing remaining files, report at end).

## Portability

- **Missing explicit `#include <string.h>` / `<unistd.h>`** — Relies on transitive includes from `<jstr/jstr.h>`. Should include explicitly for portability.
- **Static link jstring** — `cc ... /path/to/libjstr.a` instead of `.so`, avoiding `LD_LIBRARY_PATH` at runtime.
- **Add rpath to `./compile`** — `-Wl,-rpath,$DIR/lib/jstring/build/lib` so the shared library is found without env vars.
- **CMake build alternative** — For broader platform support and IDE integration.
- **`JSTR_USE_UNLOCKED_IO_READ` portability** — Line 5 enables `fread_unlocked`. Not available on all platforms (e.g., some BSDs). Verify or add `#ifdef` fallback.
- **Sync `build/include/` with `include/`** — The build copy headers are snapshots. Add regeneration step to `./compile` or document the sync process.
- **`jstr_io_writefilefd_len` writev vs write fallback** — The `io.h` write functions use `writev` for scatter-gather I/O. On platforms without `writev` (e.g., some embedded systems), there should be a `write()` fallback.

## Features

- **`G.eflags` field always zero** — Global struct field `eflags` is used at line 129 (passed to regex exec) but never modified by flag parsing. No CLI way to set eflags. Add `-e` flag to set eflags.
- **Add `--version` flag** — Standard CLI convention. Use `_(...)` macro for consistency.
- **Support `-` as stdin placeholder in file list** — `find-and-replace foo bar file1 - file2` reads stdin between file1 and file2.
- **Add `-q`/`--quiet` flag** — Suppress error messages (stderr).
- **No Unicode awareness** — All string operations use byte counts, not character counts. Backreferences can split multi-byte UTF-8 sequences. Document as limitation or add codepoint-aware replacement.
- **Consider adding `git diff`-style colored output for in-place changes** — Show diffs with color when `-i` is used with a terminal, similar to `git diff --color`.

## Library (jstring)

- **Regex empty-string matching disabled for empty buffers** — `jstr_re_rplcn_backref_len_from_exec` at `regex.h:693` has `if (jstr_unlikely(start_idx >= *sz)) return 0;` which skips regex matching entirely when the input buffer is empty. This prevents regex patterns like `^$` from matching empty files.
- **Clip `nmatch` inside `jstr_re_rplcn_backref_len_from_exec`** — Currently clipping is done at every call site (tool + tests); move into the function itself.
- **Add `find_len` parameter to `jstr_re_rplcn_*` functions** — Allows early return for empty find at library level instead of requiring every caller to guard.
- **`jstr_re_comp_len` with empty-pattern error** — New function taking `preg_len` that returns `JSTR_RE_RET_BADPAT` for empty patterns, while keeping `jstr_re_comp` POSIX-compatible.
- **`jstr_re_chk` signedness fragility** — The library uses negative values for errors. `jstr_re_chk(d)` = `d < 0`. Works but mixing signed/unsigned comparison elsewhere could miss error checks.
- **`jstr_rplcn_len_exec_j` conflates error with count** — Returns `(size_t)-1` on malloc failure, which is also a valid replacement count (`SIZE_MAX`). The tool checks this sentinel, but it's an awkward API design.
