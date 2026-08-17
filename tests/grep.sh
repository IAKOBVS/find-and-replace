#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

t_grep_stdin() {
	td=$1
	printf 'hello\nworld\n' | "$PROG" hello there --grep > "$td/out" 2>/dev/null
	rc=$?
	out=$(strip_ansi < "$td/out")
	[ "$rc" -eq 0 ] && [ "$out" = '1:hello' ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out]" > "$td/result"
}

t_grep_no_match() {
	td=$1
	printf 'hello\n' | "$PROG" xyz there --grep > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 1 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc" > "$td/result"
}

t_grep_exit_2_bad_regex() {
	td=$1
	printf 'hello\n' | "$PROG" '[' there --grep -R > /dev/null 2>&1
	rc=$?
	[ "$rc" -eq 2 ] && echo PASS > "$td/result" || echo "FAIL: bad regex should exit 2 (rc=$rc)" > "$td/result"
}

t_grep_conflict_i() {
	td=$1
	printf 'x\n' | "$PROG" x y --grep -i > /dev/null 2>&1
	rc=$?
	[ "$rc" -eq 2 ] && echo PASS > "$td/result" || echo "FAIL: --grep with -i should exit 2 (rc=$rc)" > "$td/result"
}

t_grep_conflict_c() {
	td=$1
	printf 'x\n' > "$td/f"
	"$PROG" x y --grep -c -i "$td/f" > /dev/null 2>&1
	rc=$?
	[ "$rc" -eq 2 ] && echo PASS > "$td/result" || echo "FAIL: --grep with -c should exit 2 (rc=$rc)" > "$td/result"
}

t_grep_single_file_prefix() {
	td=$1
	printf 'foo\n' > "$td/f"
	"$PROG" foo bar --grep "$td/f" > "$td/out" 2>/dev/null
	rc=$?
	exp="$td/f:1:foo"
	out=$(strip_ansi < "$td/out")
	[ "$rc" -eq 0 ] && [ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out] exp=[$exp]" > "$td/result"
}

t_grep_multiple_files() {
	td=$1
	printf 'foo\n' > "$td/f1"; printf 'foo\n' > "$td/f2"
	"$PROG" foo bar --grep "$td/f1" "$td/f2" > "$td/out" 2>/dev/null
	out=$(strip_ansi < "$td/out")
	exp="$td/f1:1:foo
$td/f2:1:foo"
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: out=[$out] exp=[$exp]" > "$td/result"
}

t_grep_recursive() {
	td=$1; mkdir -p "$td/sub"
	printf 'match\n' > "$td/sub/a.txt"; printf 'nomatch\n' > "$td/sub/b.c"; printf 'match\n' > "$td/sub/c.txt"
	"$PROG" match M --grep -r --include '\.txt$' "$td/sub" > "$td/out" 2>/dev/null
	rc=$?
	out=$(strip_ansi < "$td/out" | sort)
	exp="$td/sub/a.txt:1:match
$td/sub/c.txt:1:match"
	[ "$rc" -eq 0 ] && [ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out] exp=[$exp]" > "$td/result"
}

t_grep_regex_anchor() {
	td=$1
	printf 'alpha\nbeta\nalpha\n' | "$PROG" '^alpha' '' --grep -R > "$td/out" 2>/dev/null
	rc=$?
	exp='1:alpha
3:alpha'
	out=$(strip_ansi < "$td/out")
	[ "$rc" -eq 0 ] && [ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out] exp=[$exp]" > "$td/result"
}

t_grep_fixed() {
	td=$1
	printf 'apple\nbanana\n' | "$PROG" app x --grep > "$td/out" 2>/dev/null
	rc=$?
	out=$(strip_ansi < "$td/out")
	[ "$rc" -eq 0 ] && [ "$out" = '1:apple' ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out]" > "$td/result"
}

t_grep_empty_find() {
	td=$1
	printf 'a\nb\n' | "$PROG" '' x --grep > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 0 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc" > "$td/result"
}

t_grep_empty_input() {
	td=$1
	: | "$PROG" foo bar --grep > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 1 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc" > "$td/result"
}

t_grep_quiet() {
	td=$1
	printf 'hello\n' | "$PROG" hello x --grep -q > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 0 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc" > "$td/result"
}

t_grep_binary() {
	td=$1
	printf 'ab\x00cd' > "$td/bin"
	"$PROG" ab x --grep "$td/bin" > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 1 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: binary file should be skipped (rc=$rc)" > "$td/result"
}

t_grep_dash_stdin_placeholder() {
	td=$1
	printf 'match one\n' > "$td/f1"; printf 'match three\n' > "$td/f2"
	printf 'match two\n' > "$td/sin"
	"$PROG" match M --grep "$td/f1" - "$td/f2" < "$td/sin" > "$td/out" 2>/dev/null
	rc=$?
	exp="$td/f1:1:match one
1:match two
$td/f2:1:match three"
	out=$(strip_ansi < "$td/out")
	[ "$rc" -eq 0 ] && [ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out] exp=[$exp]" > "$td/result"
}

t_grep_exclude_cli() {
	td=$1
	printf 'keep\n' > "$td/k.txt"; printf 'ignore\n' > "$td/i.txt"
	"$PROG" keep x --grep --exclude '^i' "$td/k.txt" "$td/i.txt" > "$td/out" 2>/dev/null
	out=$(strip_ansi < "$td/out")
	[ "$out" = "$td/k.txt:1:keep" ] && echo PASS > "$td/result" || echo "FAIL: out=[$out]" > "$td/result"
}

t_grep_nonexistent_file() {
	td=$1
	"$PROG" foo bar --grep "$td/nope" > /dev/null 2>&1
	rc=$?
	[ "$rc" -eq 2 ] && echo PASS > "$td/result" || echo "FAIL: nonexistent file in --grep should exit 2 (rc=$rc)" > "$td/result"
}

TESTS="
t_grep_stdin
t_grep_no_match
t_grep_exit_2_bad_regex
t_grep_conflict_i
t_grep_conflict_c
t_grep_single_file_prefix
t_grep_multiple_files
t_grep_recursive
t_grep_regex_anchor
t_grep_fixed
t_grep_empty_find
t_grep_empty_input
t_grep_quiet
t_grep_binary
t_grep_dash_stdin_placeholder
t_grep_exclude_cli
t_grep_nonexistent_file
"
run_suite "grep mode" "$TESTS"
