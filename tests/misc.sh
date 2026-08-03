#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

t_double_dash() {
	td=$1; out=$(printf 'foo' | "$PROG" foo bar -- 2>/dev/null)
	[ "$out" = 'bar' ] && echo PASS > "$td/result" || echo "FAIL: expected [bar] got [$out]" > "$td/result"
}

t_double_dash_file() {
	td=$1; printf '%s\n' 'match' > "$td/-f"
	out=$("$PROG" match replaced -- "$td/-f" 2>/dev/null)
	printf '%s\n' "$out" | grep -q 'replaced' && echo PASS > "$td/result" || echo "FAIL: expected [replaced] got [$out]" > "$td/result"
}

t_multiline_find() {
	td=$1; out=$(printf 'a\nb\nc' | "$PROG" 'a
b' 'A B' 2>/dev/null)
	printf '%s' "$out" | cmp -s - <(printf 'A B\nc') && echo PASS > "$td/result" || echo "FAIL: got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result"
}

t_slash() {
	td=$1; out=$(printf 'a/b\n' | "$PROG" '/' '-' 2>/dev/null)
	[ "$out" = 'a-b' ] && echo PASS > "$td/result" || echo "FAIL: expected [a-b] got [$out]" > "$td/result"
}

t_overlapping() {
	td=$1; out=$(printf 'aaaa\n' | "$PROG" aa a -g 2>/dev/null)
	[ "$out" = 'aa' ] && echo PASS > "$td/result" || echo "FAIL: expected [aa] got [$out]" > "$td/result"
}

t_end_of_options() {
	td=$1; printf 'match\n' > "$td/f.txt"; printf 'match\n' > "$td/f.c"
	"$PROG" match replaced -i --exclude '*.txt' "$td/f.txt" "$td/f.c" 2>/dev/null
	ct=$(cat "$td/f.txt"); cc=$(cat "$td/f.c")
	[ "$ct" = 'match' ] && [ "$cc" = 'replaced' ] && echo PASS > "$td/result" || echo "FAIL: txt [$ct] c [$cc]" > "$td/result"
}

TESTS="
t_double_dash
t_double_dash_file
t_multiline_find
t_slash
t_overlapping
t_end_of_options
"
run_suite "miscellaneous tests" "$TESTS"
