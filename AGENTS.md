# find-and-replace

Single-file C CLI tool (`find-and-replace.c`, ~480 lines) for fixed-string or regex find-and-replace on files, with optional recursion, glob filtering, and in-place editing with backups.

## Setup & build

```
sudo ./setup   # clones lib/jstring from github.com/IAKOBVS/jstring, compiles + tests it
./build        # links against lib/jstring/build/lib/libjstr.a
sudo ./install # copies binary to $HOME/.local/bin (dir must exist)
```

- `./update` runs `git restore && ./update` inside `lib/jstring` (update jstring dependency)
- `./generate-readme` rebuilds `README.md` from `.README.md` + usage strings in source

## Key facts

- **Only ANSI C features** - no VLAs, no `//` comments, no C99+ features beyond what POSIX requires
- **Dependency**: [jstring](https://github.com/IAKOBVS/jstring) - linked statically via `lib/jstring/build/lib/libjstr.a`
- **Include path**: `lib/jstring/build/include/` (not `lib/jstring/include/`)
- **Code style**: no comments, SPDX MIT header, `clang-format off/on` around the usage string
- **Usage strings** are defined with `_(...)` macro calls in source; `generate-readme` parses these with `grep '_('`
- `.gitignore` ignores `find-and-replace` binary and `jstring/` (symlink/lib dir)
- **No linter/formatter** beyond compiler flags (`-Wall -Wextra -Wpedantic`)
- **No CI** workflows

## Tests

```
./build && tests/run.sh   # 40 integration tests
./test [N]                # integration tests + N fuzz iterations (default 500)
./tests/fuzz.sh [N]       # fuzz tests only
```

Integration tests cover: fixed-string, global/regex/case-insensitive replacement, in-place editing with backups, stdin, multiple files, recursive directory traversal, `--include`/`--exclude` filtering.

Fuzz tests generate random FIND/REPLACE/input strings and run the tool in stdin, file, and in-place modes, detecting crashes via signal exit codes.

## Known quirks

- **Combined flags with `-i`**: `-ir` treats `r` as a backup suffix, not `--recursive`. This is by design — `-i` takes an optional suffix argument, so remaining chars after `i` are consumed as the suffix. Use `-i -r` as separate args.
- **`-G`** was historically broken (set n=0). Now fixed — sets n=1 (single replacement).
- **`--include`/`--exclude`** were historically broken (glob value consumed by flag parsing but not skipped in the file pass). Now fixed.
- **`--exclude`** on command-line files was historically inverted (matching files were processed, non-matching skipped). Now fixed.
- **`tests/test.c`** is a stale stub with a broken include path; use `tests/run.sh` instead.

## Build flags (auto-detected)

`-march=native -Wall -Wextra -Wpedantic` added when cc is gcc or clang.
