#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

t_confirm_yes() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" hello bye -c -i "$td/f" 2>/dev/null)
	[ "$(cat "$td/f")" = 'bye world' ] && echo PASS > "$td/result" || echo "FAIL: expected [bye world] got [$(cat "$td/f")]" > "$td/result"
}

t_confirm_abort() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=0; printf 'n\n' | "$PROG" hello bye -c -i "$td/f" >/dev/null 2>"$td/err" || rc=$?
	[ "$rc" -ne 0 ] && grep -q 'Aborted' "$td/err" && [ "$(cat "$td/f")" = 'hello world' ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc file=[$(cat "$td/f")] err=[$(cat "$td/err")]" > "$td/result"
}

t_confirm_no_inplace_err() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=0; printf 'y\n' | "$PROG" hello bye -c "$td/f" >/dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: -c without -i should error" > "$td/result"
}

t_confirm_stdin_err() {
	td=$1; rc=0; printf 'hello\n' | "$PROG" hello bye -c -i >/dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: -c with stdin should error" > "$td/result"
}

t_confirm_no_match() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" nomatch bye -c -i "$td/f" 2>/dev/null)
	[ -z "$out" ] && [ "$(cat "$td/f")" = 'hello world' ] && echo PASS > "$td/result" || echo "FAIL: out=[$out] file=[$(cat "$td/f")]" > "$td/result"
}

t_confirm_multiline_regex() {
	td=$1; printf 'hello\nworld\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" 'hello\nworld' hi -c -i -R "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'hi' ] && printf '%s' "$clean_out" | grep -q "$td/f:1:hello" && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$out]" > "$td/result"
}

t_confirm_multi_same_line() {
	td=$1; printf 'la la\nla la\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" la lu -c -i -g "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'lu lu
lu lu' ] && [ "$(printf '%s\n' "$clean_out" | grep -c "$td/f:")" -eq 2 ] && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$out]" > "$td/result"
}

t_confirm_recursive() {
	td=$1; mkdir -p "$td/d/sub"; printf 'alpha\n' > "$td/d/f1"; printf 'beta\n' > "$td/d/sub/f2"
	out=$(printf 'y\n' | "$PROG" alpha ALPHA -c -i -r "$td/d" 2>/dev/null)
	[ "$(cat "$td/d/f1")" = 'ALPHA' ] && [ "$(cat "$td/d/sub/f2")" = 'beta' ] && echo PASS > "$td/result" || echo "FAIL: f1=[$(cat "$td/d/f1")] f2=[$(cat "$td/d/sub/f2")]" > "$td/result"
}

t_confirm_backup() {
	td=$1; printf 'hello\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" hello bye -c -i.bak "$td/f" 2>/dev/null)
	[ "$(cat "$td/f")" = 'bye' ] && [ "$(cat "$td/f.bak")" = 'hello' ] && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] bak=[$(cat "$td/f.bak" 2>/dev/null)]" > "$td/result"
}

t_confirm_stderr_reports_changed() {
	td=$1; printf 'hello world\n' > "$td/f"
	printf 'y\n' | "$PROG" hello bye -c -i "$td/f" 2>"$td/err" >/dev/null
	[ "$(cat "$td/err")" = "$td/f" ] && echo PASS > "$td/result" || echo "FAIL: stderr=[$(cat "$td/err")]" > "$td/result"
}

t_confirm_stderr_no_report_on_abort() {
	td=$1; printf 'hello world\n' > "$td/f"
	printf 'n\n' | "$PROG" hello bye -c -i "$td/f" 2>"$td/err" >/dev/null
	[ "$(cat "$td/err")" = 'Aborted.' ] && echo PASS > "$td/result" || echo "FAIL: stderr=[$(cat "$td/err")]" > "$td/result"
}

t_confirm_regex_preview_dot_star_g() {
	td=$1; printf 'hello\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" ".*" "world" -gc -i -R "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'world' ] && printf '%s' "$clean_out" | grep -q "^$td/f:1:helloworld" && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_regex_preview_skip_newline() {
	td=$1; printf ' b\n b\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" ".* b" "b" -gc -i -RE "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	# Under latest jstring, ".* b" replaced with "b" (with REG_NEWLINE) produces "b\nb\n"
	[ "$(cat "$td/f")" = 'b
b' ] && printf '%s' "$clean_out" | grep -q "^$td/f:1: bb" && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_regex_preview_backref() {
	td=$1; printf 'hello\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" "(h)ello" '\\1world' -gc -i -E "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'hworld' ] && printf '%s' "$clean_out" | grep -q "^$td/f:1:hellohworld" && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

TESTS="
t_confirm_yes
t_confirm_abort
t_confirm_no_inplace_err
t_confirm_stdin_err
t_confirm_no_match
t_confirm_multiline_regex
t_confirm_multi_same_line
t_confirm_recursive
t_confirm_backup
t_confirm_stderr_reports_changed
t_confirm_stderr_no_report_on_abort
t_confirm_regex_preview_dot_star_g
t_confirm_regex_preview_skip_newline
t_confirm_regex_preview_backref
"
run_suite "confirm tests" "$TESTS"
