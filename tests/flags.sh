#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

t_explicit_F() {
	td=$1; out=$(printf 'hello world\n' | "$PROG" hello goodbye -F 2>/dev/null)
	[ "$out" = 'goodbye world' ] && echo PASS > "$td/result" || echo "FAIL: expected [goodbye world] got [$out]" > "$td/result"
}

t_literal_F_with_dot() {
	td=$1; out=$(printf 'a.b\n' | "$PROG" a.b X -F 2>/dev/null)
	[ "$out" = 'X' ] && echo PASS > "$td/result" || echo "FAIL: expected [X] got [$out]" > "$td/result"
}

t_ignore_case() {
	td=$1; out=$(printf 'Hello World\n' | "$PROG" hello hi -I 2>/dev/null)
	[ "$out" = 'hi World' ] && echo PASS > "$td/result" || echo "FAIL: expected [hi World] got [$out]" > "$td/result"
}

t_global_ignore_case() {
	td=$1; out=$(printf 'AaA AaA AaA\n' | "$PROG" aaa xxx -I -g 2>/dev/null)
	[ "$out" = 'xxx xxx xxx' ] && echo PASS > "$td/result" || echo "FAIL: expected [xxx xxx xxx] got [$out]" > "$td/result"
}

t_case_sensitive() {
	td=$1; out=$(printf 'Hello\n' | "$PROG" hello bye 2>/dev/null)
	[ "$out" = 'Hello' ] && echo PASS > "$td/result" || echo "FAIL: expected [Hello] got [$out]" > "$td/result"
}

t_Z_flag() {
	td=$1; out=$(printf 'a\nb\n' | "$PROG" '^b' 'B' -RZ 2>/dev/null)
	case "$out" in
		"$(printf 'a\nB')"|"$(printf 'a\nB\n')") echo PASS > "$td/result" ;;
		*) echo "FAIL: Z flag expected [a.B] got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result" ;;
	esac
}

t_z_flag() {
	td=$1; out=$(printf 'a\nb\n' | "$PROG" '^b' 'B' -Rz 2>/dev/null)
	[ "$out" = "$(printf 'a\nb\n')" ] || [ "$out" = "$(printf 'a\nb')" ] && echo PASS > "$td/result" || echo "FAIL: z flag, expected unchanged [a.b.] got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result"
}

t_help() {
	td=$1; "$PROG" foo bar -h > /dev/null 2>&1 && echo PASS > "$td/result" || echo "FAIL: -h should exit 0" > "$td/result"
}

t_global_then_G() {
	td=$1; out=$(printf 'la la la\n' | "$PROG" la lu -Gg 2>/dev/null)
	[ "$out" = 'lu lu lu' ] && echo PASS > "$td/result" || echo "FAIL: expected [lu lu lu] got [$out]" > "$td/result"
}

t_G_then_global() {
	td=$1; out=$(printf 'la la la\n' | "$PROG" la lu -gG 2>/dev/null)
	[ "$out" = 'lu la la' ] && echo PASS > "$td/result" || echo "FAIL: expected [lu la la] got [$out]" > "$td/result"
}

t_flag_order_F_R() {
	td=$1; out=$(printf 'foo\n' | "$PROG" foo bar -F -R 2>/dev/null)
	[ "$out" = 'bar' ] && echo PASS > "$td/result" || echo "FAIL: expected [bar] got [$out]" > "$td/result"
}

t_flag_order_R_F() {
	td=$1; out=$(printf 'foo\n' | "$PROG" foo bar -R -F 2>/dev/null)
	[ "$out" = 'bar' ] && echo PASS > "$td/result" || echo "FAIL: expected [bar] got [$out]" > "$td/result"
}

t_flag_order_Z_z() {
	td=$1; nl=$(printf '\n_'); nl="${nl%_}"; inp="a${nl}b"
	out=$(printf '%s' "$inp" | "$PROG" '^b' 'B' -R -Z -z 2>/dev/null)
	exp="a${nl}b"
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: expected [a<NL>b] got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result"
}

t_flag_order_z_Z() {
	td=$1; nl=$(printf '\n_'); nl="${nl%_}"; inp="a${nl}b"
	out=$(printf '%s' "$inp" | "$PROG" '^b' 'B' -R -z -Z 2>/dev/null)
	exp="a${nl}B"
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: expected [a<NL>B] got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result"
}

TESTS="
t_explicit_F
t_literal_F_with_dot
t_ignore_case
t_global_ignore_case
t_case_sensitive
t_Z_flag
t_z_flag
t_help
t_global_then_G
t_G_then_global
t_flag_order_F_R
t_flag_order_R_F
t_flag_order_Z_z
t_flag_order_z_Z
"
run_suite "flag tests" "$TESTS"
