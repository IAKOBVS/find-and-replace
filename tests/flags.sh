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

t_flag_between_files_regex() {
	td=$1
	printf 'abc123\n' > "$td/a1"
	printf 'abc123\n' > "$td/a2"
	"$PROG" '[0-9]+' X -i "$td/a1" -R -E "$td/a2" 2>/dev/null
	rc=$?
	a1=$(cat "$td/a1"); a2=$(cat "$td/a2")
	[ "$rc" -eq 0 ] && [ "$a1" = 'abc123' ] && [ "$a2" = 'abcX' ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc a1=[$a1] a2=[$a2]" > "$td/result"
}

t_flag_between_files_fixed() {
	td=$1
	printf 'abc123\n' > "$td/b1"
	printf 'abc123\n' > "$td/b2"
	"$PROG" '[0-9]+' X -R -E -i "$td/b1" -F "$td/b2" 2>/dev/null
	rc=$?
	b1=$(cat "$td/b1"); b2=$(cat "$td/b2")
	[ "$rc" -eq 0 ] && [ "$b1" = 'abcX' ] && [ "$b2" = 'abc123' ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc b1=[$b1] b2=[$b2]" > "$td/result"
}

t_version() {
	td=$1
	out=$("$PROG" --version 2>/dev/null)
	rc=$?
	if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q 'find-and-replace'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc out=[$out]" > "$td/result"
	fi
}

t_single_h() {
	td=$1
	rc=0
	"$PROG" -h > "$td/usage" 2>/dev/null || rc=$?
	if [ "$rc" -eq 0 ] && [ -s "$td/usage" ] && grep -q 'Usage' "$td/usage"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc usage_bytes=$(wc -c < "$td/usage" 2>/dev/null)" > "$td/result"
	fi
}

t_exclude_invalid_regex() {
	td=$1
	printf 'xyz\n' > "$td/f"
	rc=0
	"$PROG" x y --exclude '[' "$td/f" >/dev/null 2>"$td/err" || rc=$?
	if [ "$rc" -ne 0 ] && grep -q -- '--exclude' "$td/err" && grep -q 'not a valid regex' "$td/err" && [ "$(cat "$td/f")" = 'xyz' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc err=[$(cat "$td/err")] file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_version_flag_mid_args() {
	td=$1
	out=$("$PROG" foo bar --version 2>/dev/null)
	rc=$?
	if [ "$rc" -eq 0 ] && [ "$out" = 'find-and-replace 0.1.0' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc out=[$out]" > "$td/result"
	fi
}

t_v_flag_mid_args() {
	td=$1
	out=$("$PROG" foo bar -v 2>/dev/null)
	rc=$?
	if [ "$rc" -eq 0 ] && [ "$out" = 'find-and-replace 0.1.0' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc out=[$out]" > "$td/result"
	fi
}

t_l_flag_cli() {
	td=$1
	printf 'foo\n' > "$td/f"
	out=$("$PROG" foo bar -l -i "$td/f" 2>/dev/null)
	rc=$?
	content=$(cat "$td/f")
	if [ "$rc" -eq 0 ] && [ "$content" = 'bar' ] && printf '%s' "$out" | grep -q "$td/f"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc content=[$content] out=[$out]" > "$td/result"
	fi
}

t_quiet_inplace() {
	td=$1
	printf 'hello\n' > "$td/f"
	"$PROG" hello bye -i -q "$td/f" 2>"$td/err" >/dev/null
	[ "$(cat "$td/f")" = 'bye' ] && [ ! -s "$td/err" ] && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] err=[$(cat "$td/err")]" > "$td/result"
}

t_quiet_long_flag() {
	td=$1
	printf 'hello\n' > "$td/f"
	"$PROG" hello bye -i --quiet "$td/f" 2>"$td/err" >/dev/null
	[ "$(cat "$td/f")" = 'bye' ] && [ ! -s "$td/err" ] && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] err=[$(cat "$td/err")]" > "$td/result"
}

t_exclude_long_relative_path() {
	td=$1
	printf 'zzz\n' > "$td/f"
	mkdir -p "$td/a"
	len_td=${#td}
	R=$(( (4092 - len_td) / 5 ))
	P="$td/"
	i=0
	while [ $i -lt "$R" ]; do
		P="${P}a/../"
		i=$((i + 1))
	done
	P="${P}f"
	rc=0
	"$PROG" zzz ZZZ -i "$P" >/dev/null 2>"$td/err" || rc=$?
	if [ "$rc" -ne 0 ] && [ "$(cat "$td/f")" = 'zzz' ] && grep -q 'too large to create a backup file' "$td/err"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc len_P=${#P} err=[$(cat "$td/err")] file=[$(cat "$td/f")]" > "$td/result"
	fi
}

# REPLACE argument can be omitted when --grep is used; argv[2] is a flag.
t_grep_omit_replace() {
	td=$1
	printf 'test line\nfoo bar\n' > "$td/in"
	"$PROG" 't' x --grep "$td/in" > "$td/out" 2>/dev/null
	rc=$?
	if [ "$rc" -eq 0 ] && grep -q 'test line' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc out=[$(cat "$td/out")]" > "$td/result"
	fi
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
t_flag_between_files_regex
t_flag_between_files_fixed
t_version
t_single_h
t_exclude_invalid_regex
t_version_flag_mid_args
t_v_flag_mid_args
t_l_flag_cli
t_quiet_inplace
t_quiet_long_flag
t_exclude_long_relative_path
t_grep_omit_replace
"
run_suite "flag tests" "$TESTS"
