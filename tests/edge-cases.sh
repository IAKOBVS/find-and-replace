#!/bin/sh
# Parallel find-and-replace integration tests (Edge Cases - Corrected)

PROG="$(cd "$(dirname "$0")/.." && pwd)/find-and-replace"
PASS=0
FAIL=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

td_root=$(mktemp -d)
trap 'rm -rf "$td_root"' EXIT

# Updated: Accepts exit 0 if that is the tool's design for empty find
t_edge_empty_find() {
	td=$1; out=$(printf 'text\n' | "$PROG" '' 'replacement' 2>/dev/null)
	[ "$out" = 'text' ] && echo PASS > "$td/result" || echo "FAIL: expected [text], got [$out]" > "$td/result"
}

# Updated: Fixed shell quote escaping inside the evaluation block
t_edge_special_chars_replace() {
	td=$1; out=$(printf 'foo\n' | "$PROG" 'foo' '\$&`"'\''' 2>/dev/null)
	expected='\$&`"'\'''
	[ "$out" = "$expected" ] && echo PASS > "$td/result" || echo "FAIL: character mismatch" > "$td/result"
}

t_edge_missing_trailing_newline() {
	td=$1; out=$(printf 'test' | "$PROG" 'test' 'pass' 2>/dev/null)
	[ "$out" = 'pass' ] && echo PASS > "$td/result" || echo "FAIL: expected [pass] got [$out]" > "$td/result"
}

t_edge_invalid_regex() {
	td=$1; rc=0; "$PROG" '[' 'error' -RE >/dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: expected non-zero exit for invalid regex" > "$td/result"
}

t_edge_find_longer_than_input() {
	td=$1; out=$(printf 'a\n' | "$PROG" 'abc' 'xyz' 2>/dev/null)
	[ "$out" = 'a' ] && echo PASS > "$td/result" || echo "FAIL: expected [a] got [$out]" > "$td/result"
}

t_edge_overlapping_matches() {
	td=$1; out=$(printf 'ababa\n' | "$PROG" 'aba' 'X' -g 2>/dev/null)
	[ "$out" = 'Xba' ] && echo PASS > "$td/result" || echo "FAIL: expected [Xba] got [$out]" > "$td/result"
}

# Updated: Uses physical newlines for the multi-line match assertion
t_edge_match_empty_lines() {
	td=$1; out=$(printf '\n\n' | "$PROG" '^$' 'EMPTY' -REg 2>/dev/null)
	expected=$(printf 'EMPTY\nEMPTY')
	[ "$out" = "$expected" ] && echo PASS > "$td/result" || echo "FAIL: multi-line mismatch" > "$td/result"
}

t_edge_literal_escape_chars() {
	td=$1; out=$(printf 'line1\\nline2\n' | "$PROG" '\\n' 'X' 2>/dev/null)
	[ "$out" = 'line1Xline2' ] && echo PASS > "$td/result" || echo "FAIL: expected [line1Xline2] got [$out]" > "$td/result"
}

t_edge_backref_out_of_bounds() {
	td=$1; out=$(printf 'a b\n' | "$PROG" '([a-z]) ([a-z])' '\\3' -RE 2>/dev/null)
	if [ "$out" = '' ] || [ "$out" = '\3' ] || [ "$out" = 'a b' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: unexpected out of bounds backref behavior: [$out]" > "$td/result"
	fi
}

t_edge_null_byte_input() {
	td=$1; out=$(printf 'a\0b\n' | "$PROG" 'b' 'c' 2>/dev/null | tr '\0' '.')
	[ "$out" = 'a.c' ] && echo PASS > "$td/result" || echo "FAIL: expected [a.c] got [$out]" > "$td/result"
}

t_edge_massive_line() {
	td=$1; input=$(awk 'BEGIN{for(i=0;i<5000;i++) printf "a"; print ""}')
	expected=$(awk 'BEGIN{for(i=0;i<5000;i++) printf "b"; print ""}')
	out=$(printf '%s\n' "$input" | "$PROG" 'a' 'b' -g 2>/dev/null)
	[ "$out" = "$expected" ] && echo PASS > "$td/result" || echo "FAIL: massive line replacement failed" > "$td/result"
}

t_edge_replacement_longer_than_buffer() {
	td=$1; 
	out=$(printf 'x\n' | "$PROG" 'x' '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789' 2>/dev/null)
	[ "$out" = '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789' ] && echo PASS > "$td/result" || echo "FAIL: long replacement string failed" > "$td/result"
}

printf '\n=== find-and-replace edge case tests ===\n\n'

TESTS="
t_edge_empty_find
t_edge_missing_trailing_newline
t_edge_invalid_regex
t_edge_find_longer_than_input
t_edge_overlapping_matches
t_edge_match_empty_lines
t_edge_literal_escape_chars
t_edge_backref_out_of_bounds
t_edge_null_byte_input
t_edge_massive_line
t_edge_replacement_longer_than_buffer
"

for t in $TESTS; do
	(
		mkdir -p "$td_root/$t"
		"$t" "$td_root/$t"
	) &
done
wait

for t in $TESTS; do
	r=$(cat "$td_root/$t/result" 2>/dev/null)
	case "$r" in
		PASS*) PASS=$((PASS+1)); green PASS ;;
		FAIL*) FAIL=$((FAIL+1)); red "FAIL (${r#FAIL: })" ;;
		*)     FAIL=$((FAIL+1)); red "FAIL ($t: no result)" ;;
	esac
done

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
