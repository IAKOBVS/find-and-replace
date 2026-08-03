#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

t_tab_escape() {
	td=$1; out=$(printf 'a\tb\n' | "$PROG" '\t' 'TAB' 2>/dev/null)
	[ "$out" = 'aTABb' ] && echo PASS > "$td/result" || echo "FAIL: expected [aTABb] got [$out]" > "$td/result"
}

t_octal_escape() {
	td=$1; out=$(printf 'A\n' | "$PROG" '\101' 'X' 2>/dev/null)
	[ "$out" = 'X' ] && echo PASS > "$td/result" || echo "FAIL: expected [X] got [$out]" > "$td/result"
}

t_newlines_in_replace() {
	td=$1; out=$(printf 'a\n' | "$PROG" a 'x\ny\nz' 2>/dev/null)
	printf '%s' "$out" > "$td/out"
	printf 'x\ny\nz' > "$td/exp"
	cmp -s "$td/out" "$td/exp" && echo PASS > "$td/result" || echo "FAIL: newlines in replace" > "$td/result"
}

t_escape_in_replace() {
	td=$1; out=$(printf 'hello\n' | "$PROG" hello 'x\ny' 2>/dev/null)
	printf '%s' "$out" > "$td/out"
	printf 'x\ny' > "$td/exp"
	cmp -s "$td/out" "$td/exp" && echo PASS > "$td/result" || echo "FAIL: expected [x<NL>y] got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result"
}

t_escape_ff() {
	td=$1; out=$(printf 'a\fb\n' | "$PROG" '\f' 'FF' 2>/dev/null)
	[ "$out" = 'aFFb' ] && echo PASS > "$td/result" || echo "FAIL: expected [aFFb] got [$out]" > "$td/result"
}

t_escape_cr() {
	td=$1; out=$(printf 'a\rb\n' | "$PROG" '\r' 'CR' 2>/dev/null)
	[ "$out" = 'aCRb' ] && echo PASS > "$td/result" || echo "FAIL: expected [aCRb] got [$out]" > "$td/result"
}

t_escape_vt() {
	td=$1; out=$(printf 'a\vb\n' | "$PROG" '\v' 'VT' 2>/dev/null)
	[ "$out" = 'aVTb' ] && echo PASS > "$td/result" || echo "FAIL: expected [aVTb] got [$out]" > "$td/result"
}

t_escape_bs() {
	td=$1; out=$(printf 'a\bb\n' | "$PROG" '\b' 'BS' 2>/dev/null)
	[ "$out" = 'aBSb' ] && echo PASS > "$td/result" || echo "FAIL: expected [aBSb] got [$out]" > "$td/result"
}

t_escape_various_in_replace() {
	td=$1
	printf 'a\n' | "$PROG" a '\b\f\r\t\v' 2>/dev/null > "$td/out"
	printf '\b\f\r\t\v\n' > "$td/exp"
	cmp -s "$td/out" "$td/exp" && echo PASS > "$td/result" || echo "FAIL: escape sequence mismatch" > "$td/result"
}

TESTS="
t_tab_escape
t_octal_escape
t_newlines_in_replace
t_escape_in_replace
t_escape_ff
t_escape_cr
t_escape_vt
t_escape_bs
t_escape_various_in_replace
"
run_suite "escape sequence tests" "$TESTS"
