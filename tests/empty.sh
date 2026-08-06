#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

t_empty_find_regex() {
	td=$1; out=$(printf 'abc\n' | "$PROG" '' 'X' -R 2>/dev/null)
	[ "$out" = 'abc' ] && echo PASS > "$td/result" || echo "FAIL: expected [abc] got [$out]" > "$td/result"
}

t_empty_find_global() {
	td=$1; out=$(printf 'abc\n' | "$PROG" '' 'X' -g 2>/dev/null)
	[ "$out" = 'abc' ] && echo PASS > "$td/result" || echo "FAIL: expected [abc] got [$out]" > "$td/result"
}

t_empty_find_inplace() {
	td=$1; printf 'abc\n' > "$td/f"
	"$PROG" '' 'X' -i "$td/f" 2>/dev/null
	content=$(cat "$td/f")
	[ "$content" = 'abc' ] && echo PASS > "$td/result" || echo "FAIL: expected [abc] got [$content]" > "$td/result"
}

t_empty_find_stdin_only() {
	td=$1; out=$(printf 'hello\n' | "$PROG" '' 'X' 2>/dev/null)
	[ "$out" = 'hello' ] && echo PASS > "$td/result" || echo "FAIL: expected [hello] got [$out]" > "$td/result"
}

t_z_flag_with_empty_find() {
	td=$1; out=$(printf 'abc\n' | "$PROG" '' X -Rz 2>/dev/null)
	[ "$out" = 'abc' ] && echo PASS > "$td/result" || echo "FAIL: expected [abc] got [$out]" > "$td/result"
}

TESTS="
t_empty_find_regex
t_empty_find_global
t_empty_find_inplace
t_empty_find_stdin_only
t_z_flag_with_empty_find
"
run_suite "empty find tests" "$TESTS"
