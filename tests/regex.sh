#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

t_regex() {
	td=$1; out=$(printf 'abc123def\n' | "$PROG" '[0-9][0-9][0-9]' 'NUM' -R 2>/dev/null)
	[ "$out" = 'abcNUMdef' ] && echo PASS > "$td/result" || echo "FAIL: expected [abcNUMdef] got [$out]" > "$td/result"
}

t_extended_regex() {
	td=$1; out=$(printf 'foo bar baz\n' | "$PROG" '(foo|bar)' 'X' -E 2>/dev/null)
	[ "$out" = 'X bar baz' ] && echo PASS > "$td/result" || echo "FAIL: expected [X bar baz] got [$out]" > "$td/result"
}

t_global_regex() {
	td=$1; out=$(printf 'a1b2c3\n' | "$PROG" '[0-9]' 'X' -Rg 2>/dev/null)
	[ "$out" = 'aXbXcX' ] && echo PASS > "$td/result" || echo "FAIL: expected [aXbXcX] got [$out]" > "$td/result"
}

t_backreference() {
	td=$1; out=$(printf 'abc def\n' | "$PROG" '([a-z]+) ([a-z]+)' '\\2 \\1' -RE 2>/dev/null)
	[ "$out" = 'def abc' ] && echo PASS > "$td/result" || echo "FAIL: expected [def abc] got [$out]" > "$td/result"
}

t_G_with_regex_backref() {
	td=$1; out=$(printf 'abc def ghi\n' | "$PROG" '([a-z]+) ([a-z]+)' '\\2 \\1' -REG 2>/dev/null)
	[ "$out" = 'def abc ghi' ] && echo PASS > "$td/result" || echo "FAIL: expected [def abc ghi] got [$out]" > "$td/result"
}

t_regex_basic_no_backref() {
	td=$1; out=$(printf 'abc123def\n' | "$PROG" '[a-z]*[0-9][0-9]*[a-z]*' 'NUM' -R 2>/dev/null)
	[ "$out" = 'NUM' ] && echo PASS > "$td/result" || echo "FAIL: expected [NUM] got [$out]" > "$td/result"
}

t_inplace_regex() {
	td=$1; printf 'abc123def\n' > "$td/f"
	"$PROG" '[0-9]+' 'NUM' -i -E "$td/f" 2>/dev/null
	content=$(cat "$td/f")
	[ "$content" = 'abcNUMdef' ] && echo PASS > "$td/result" || echo "FAIL: expected [abcNUMdef] got [$content]" > "$td/result"
}

t_inplace_global_regex() {
	td=$1; printf 'x1x2x3\n' > "$td/f"
	"$PROG" '[0-9]' 'N' -i -E -g "$td/f" 2>/dev/null
	content=$(cat "$td/f")
	[ "$content" = 'xNxNxN' ] && echo PASS > "$td/result" || echo "FAIL: expected [xNxNxN] got [$content]" > "$td/result"
}

t_empty_file_regex_anchors() {
	td=$1
	printf '\n' > "$td/emptyline"
	"$PROG" '^$' 'EMPTY' -i -R "$td/emptyline" 2>/dev/null
	content=$(cat "$td/emptyline")
	[ "$content" = 'EMPTY' ] && echo PASS > "$td/result" || echo "FAIL: expected [EMPTY] got [$content]" > "$td/result"
}

t_z_with_regex() {
	td=$1; out=$(printf 'hello\nworld\n' | "$PROG" 'hello$' 'HI' -Rz 2>/dev/null)
	case "$out" in
		"$(printf 'hello\nworld')"|"$(printf 'hello\nworld\n')") echo PASS > "$td/result" ;;
		*) echo "FAIL: z+regex expected unchanged got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result" ;;
	esac
}

t_Z_with_regex() {
	td=$1; out=$(printf 'hello\nworld\n' | "$PROG" 'hello$' 'HI' -RZ 2>/dev/null)
	case "$out" in
		"$(printf 'HI\nworld')"|"$(printf 'HI\nworld\n')") echo PASS > "$td/result" ;;
		*) echo "FAIL: Z+regex expected HI.world got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result" ;;
	esac
}

t_regex_G_then_g() {
	td=$1; out=$(printf 'a1b2c3\n' | "$PROG" '[0-9]' 'X' -RGg 2>/dev/null)
	[ "$out" = 'aXbXcX' ] && echo PASS > "$td/result" || echo "FAIL: expected [aXbXcX] got [$out]" > "$td/result"
}

t_regex_g_then_G() {
	td=$1; out=$(printf 'a1b2c3\n' | "$PROG" '[0-9]' 'X' -RgG 2>/dev/null)
	[ "$out" = 'aXb2c3' ] && echo PASS > "$td/result" || echo "FAIL: expected [aXb2c3] got [$out]" > "$td/result"
}

t_escape_in_regex() {
	td=$1; out=$(printf 'a\tb\n' | "$PROG" '\t' 'TAB' -R 2>/dev/null)
	[ "$out" = 'aTABb' ] && echo PASS > "$td/result" || echo "FAIL: expected [aTABb] got [$out]" > "$td/result"
}

t_backref_exceeds_nsub_inplace() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=0
	"$PROG" '(hello)' '\\1\\2' -E -R -i "$td/f" >/dev/null 2>"$td/err" || rc=$?
	if [ "$rc" -ne 0 ] && grep -q 'Replace backreference \\2 exceeds find capture groups (1)' "$td/err"; then
		[ "$(cat "$td/f")" = 'hello world' ] && echo PASS > "$td/result" || echo "FAIL: file changed" > "$td/result"
	else
		echo "FAIL: rc=$rc err=[$(cat "$td/err" 2>/dev/null)]" > "$td/result"
	fi
}

t_backref_within_nsub_inplace() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=0
	"$PROG" '(hello) (world)' '\\2 \\1' -E -R -i "$td/f" >/dev/null 2>"$td/err" || rc=$?
	if [ "$rc" -eq 0 ] && [ "$(cat "$td/f")" = 'world hello' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc f=[$(cat "$td/f" 2>/dev/null)] err=[$(cat "$td/err" 2>/dev/null)]" > "$td/result"
	fi
}

TESTS="
t_regex
t_extended_regex
t_global_regex
t_backreference
t_G_with_regex_backref
t_regex_basic_no_backref
t_inplace_regex
t_inplace_global_regex
t_empty_file_regex_anchors
t_z_with_regex
t_Z_with_regex
t_regex_G_then_g
t_regex_g_then_G
t_escape_in_regex
t_backref_exceeds_nsub_inplace
t_backref_within_nsub_inplace
"
run_suite "regex tests" "$TESTS"
