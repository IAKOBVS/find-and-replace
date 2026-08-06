#!/bin/bash
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

t_confirm_yes() {
	td=$1; echo 'hello world' > "$td/f"; echo 'la la la' >> "$td/f"
	out=$(echo 'y' | "$PROG" hello bye -c -i "$td/f" 2>&1)
	content=$(cat "$td/f")
	echo 'bye world' > "$td/exp"
	echo 'la la la' >> "$td/exp"
	echo "$out" | grep -q 'f:1:' && cmp -s "$td/f" "$td/exp" && echo PASS > "$td/result" || echo "FAIL: out=[$out] content=[$content]" > "$td/result"
}

t_confirm_abort() {
	td=$1; echo 'hello world' > "$td/f"; echo 'la la la' >> "$td/f"
	rc=0; out=$(echo 'n' | "$PROG" hello bye -c -i "$td/f" 2>&1) || rc=$?
	content=$(cat "$td/f")
	echo 'hello world' > "$td/exp"
	echo 'la la la' >> "$td/exp"
	[ "$rc" -ne 0 ] && echo "$out" | grep -q 'Aborted.' && cmp -s "$td/f" "$td/exp" && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out] content=[$content]" > "$td/result"
}

t_confirm_no_inplace_error() {
	td=$1; echo 'hello' > "$td/f"
	rc=0; out=$("$PROG" hello bye -c "$td/f" 2>&1) || rc=$?
	[ "$rc" -ne 0 ] && echo "$out" | grep -q 'requires' && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out]" > "$td/result"
}

t_confirm_stdin_error() {
	td=$1
	rc=0; out=$("$PROG" hello bye -c -i 2>&1) || rc=$?
	[ "$rc" -ne 0 ] && echo "$out" | grep -q 'stdin' && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out]" > "$td/result"
}

t_confirm_multi_matches() {
	td=$1; echo 'la la la' > "$td/f"
	out=$(echo 'y' | "$PROG" la lu -g -c -i "$td/f" 2>&1)
	count=$(echo "$out" | grep -c 'f:1:')
	[ "$count" -eq 1 ] && echo PASS > "$td/result" || echo "FAIL: expected 1 line with f:1:, got $count in [$out]" > "$td/result"
}

t_confirm_no_match() {
	td=$1; echo 'hello world' > "$td/f"
	out=$("$PROG" abc def -c -i "$td/f" < /dev/null)
	content=$(cat "$td/f")
	[ "$out" = "" ] && [ "$content" = 'hello world' ] && echo PASS > "$td/result" || echo "FAIL: out=[$out] content=[$content]" > "$td/result"
}

t_confirm_multiline_match() {
	td=$1; echo 'hello' > "$td/f"; echo 'world' >> "$td/f"
	out=$(echo 'y' | "$PROG" 'hello\nworld' 'hi' -c -i -R "$td/f" 2>&1)
	content=$(cat "$td/f")
	echo 'hi' > "$td/exp"
	echo "$out" | grep -q 'f:1:' && echo "$out" | grep -q 'f:2:' && cmp -s "$td/f" "$td/exp" && echo PASS > "$td/result" || echo "FAIL: out=[$out] content=[$content]" > "$td/result"
}

t_confirm_recursive() {
	td=$1; mkdir -p "$td/sub"
	echo 'la la' > "$td/sub/f1"
	echo 'la la la' > "$td/sub/f2"
	out=$(echo 'y' | "$PROG" la lu -g -c -i -r "$td/sub" 2>&1)
	c1=$(cat "$td/sub/f1")
	c2=$(cat "$td/sub/f2")
	echo "$out" | grep -q 'f1:1:' && echo "$out" | grep -q 'f2:1:' && [ "$c1" = 'lu lu' ] && [ "$c2" = 'lu lu lu' ] && echo PASS > "$td/result" || echo "FAIL: c1=[$c1] c2=[$c2]" > "$td/result"
}

TESTS="
t_confirm_yes
t_confirm_abort
t_confirm_no_inplace_error
t_confirm_stdin_error
t_confirm_multi_matches
t_confirm_no_match
t_confirm_multiline_match
t_confirm_recursive
"
run_suite "confirm tests" "$TESTS"
