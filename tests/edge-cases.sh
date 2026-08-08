#!/bin/bash
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

t_edge_empty_find() {
	td=$1; out=$(printf 'text\n' | "$PROG" '' 'replacement' 2>/dev/null)
	[ "$out" = 'text' ] && echo PASS > "$td/result" || echo "FAIL: expected [text], got [$out]" > "$td/result"
}

t_edge_special_chars_replace() {
	td=$1; out=$(printf 'foo\n' | "$PROG" 'foo' 'bar$baz' 2>/dev/null)
	[ "$out" = 'bar$baz' ] && echo PASS > "$td/result" || echo "FAIL: special chars replace got [$out]" > "$td/result"
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

t_edge_match_empty_lines() {
	td=$1; out=$(printf '\n\n' | "$PROG" '^$' 'EMPTY' -REg 2>/dev/null)
	expected=$(printf 'EMPTY\nEMPTY\nEMPTY\n')
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
	td=$1
	out=$(printf 'x\n' | "$PROG" 'x' '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789' 2>/dev/null)
	[ "$out" = '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789' ] && echo PASS > "$td/result" || echo "FAIL: long replacement string failed" > "$td/result"
}

t_edge_empty_file_inplace() {
	td=$1; : > "$td/empty"; "$PROG" foo bar -i "$td/empty" 2>/dev/null
	content=$(cat "$td/empty")
	[ "$content" = '' ] && echo PASS > "$td/result" || echo "FAIL: expected empty got [$content]" > "$td/result"
}

t_edge_regex_anchor_z() {
	td=$1; out=$(printf 'abc\ndef\n' | "$PROG" '^abc$' 'MATCH' -Rz 2>/dev/null)
	[ "$out" = "$(printf 'abc\ndef')" ] || [ "$out" = "$(printf 'abc\ndef\n')" ] && echo PASS > "$td/result" || echo "FAIL: expected unchanged got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result"
}

t_edge_many_matches() {
	td=$1; input=$(awk 'BEGIN{for(i=0;i<100;i++) printf "x"}')
	out=$(printf '%s\n' "$input" | "$PROG" x y -g 2>/dev/null)
	expected=$(awk 'BEGIN{for(i=0;i<100;i++) printf "y"}')
	[ "$out" = "$expected" ] && echo PASS > "$td/result" || echo "FAIL: many matches mismatch" > "$td/result"
}

t_edge_unicode_bytes() {
	td=$1; out=$(printf '\xc3\xa9\n' | "$PROG" '\303\251' 'e' 2>/dev/null)
	[ "$out" = 'e' ] && echo PASS > "$td/result" || echo "FAIL: unicode replacement mismatch got [$out]" > "$td/result"
}

t_edge_readonly_file_backup() {
	td=$1; printf 'content\n' > "$td/f"; chmod 0444 "$td/f"
	"$PROG" content replaced -i.bak "$td/f" > /dev/null 2>&1
	rc=$?; chmod 0644 "$td/f"
	[ "$rc" -eq 0 ] && cmp -s "$td/f.bak" <(printf 'content\n') && [ "$(cat "$td/f")" = 'replaced' ] && echo PASS > "$td/result" || echo "FAIL: read-only with backup failed (rc=$rc)" > "$td/result"
}

t_edge_nonexistent_dir_recursive() {
	td=$1; rc=0; "$PROG" foo bar -i -r "$td/nonexistent" > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: nonexistent dir with -r should error" > "$td/result"
}

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
t_edge_special_chars_replace
t_edge_replacement_longer_than_buffer
t_edge_empty_file_inplace
t_edge_regex_anchor_z
t_edge_many_matches
t_edge_unicode_bytes
t_edge_readonly_file_backup
t_edge_nonexistent_dir_recursive
"
run_suite "edge case tests" "$TESTS"
