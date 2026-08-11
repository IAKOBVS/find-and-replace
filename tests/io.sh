#!/bin/bash
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

t_backup_content_identity() {
	td=$1; printf 'original content\nsecond line\n' > "$td/f"
	"$PROG" original replaced -i.bak "$td/f" > /dev/null 2>&1
	cmp -s "$td/f.bak" <(printf 'original content\nsecond line\n') && [ "$(cat "$td/f")" = "$(printf 'replaced content\nsecond line')" ] && echo PASS > "$td/result" || echo "FAIL: backup content mismatch" > "$td/result"
}

t_backup_empty_file() {
	td=$1; printf 'content\n' > "$td/f"
	"$PROG" content '' -i.bak "$td/f" > /dev/null 2>&1
	cmp -s "$td/f.bak" <(printf 'content\n') && [ "$(wc -c < "$td/f")" -eq 1 ] && echo PASS > "$td/result" || echo "FAIL: expected file=just-newline with backup" > "$td/result"
}

t_backup_binary_content() {
	td=$1; printf 'abc\x00def\n' > "$td/f"
	"$PROG" def xyz -i.bak "$td/f" > /dev/null 2>&1
	[ ! -e "$td/f.bak" ] && [ "$(tr '\0' '0' < "$td/f")" = 'abc0def' ] && echo PASS > "$td/result" || echo "FAIL: binary file should be skipped (bak exists: $([ -e "$td/f.bak" ] && echo yes || echo no), file [$(tr '\0' '0' < "$td/f")])" > "$td/result"
}

t_backup_multi_file() {
	td=$1; printf 'alpha\n' > "$td/f1"; printf 'beta\n' > "$td/f2"
	"$PROG" alpha aaaa -i.bak "$td/f1" "$td/f2" > /dev/null 2>&1
	c1=$(cat "$td/f1"); c2=$(cat "$td/f2"); b1=$(cat "$td/f1.bak" 2>/dev/null || echo 'NONE')
	[ "$c1" = 'aaaa' ] && [ "$c2" = 'beta' ] && [ "$b1" = 'alpha' ] && echo PASS > "$td/result" || echo "FAIL: f1 [$c1] f2 [$c2] b1 [$b1]" > "$td/result"
}

t_inplace_shorter() {
	td=$1; printf 'abcdefgh\n' > "$td/f"
	"$PROG" cdef xy -i "$td/f" > /dev/null 2>&1
	[ "$(cat "$td/f")" = 'abxygh' ] && echo PASS > "$td/result" || echo "FAIL: expected [abxygh] got [$(cat "$td/f")]" > "$td/result"
}

t_inplace_longer() {
	td=$1; printf 'ab\n' > "$td/f"
	"$PROG" ab 'much longer replacement' -i "$td/f" > /dev/null 2>&1
	[ "$(cat "$td/f")" = 'much longer replacement' ] && echo PASS > "$td/result" || echo "FAIL: expected [much longer replacement] got [$(cat "$td/f")]" > "$td/result"
}

t_inplace_same_length() {
	td=$1; printf 'abc\n' > "$td/f"
	"$PROG" abc xyz -i "$td/f" > /dev/null 2>&1
	[ "$(cat "$td/f")" = 'xyz' ] && echo PASS > "$td/result" || echo "FAIL: expected [xyz] got [$(cat "$td/f")]" > "$td/result"
}

t_inplace_identical() {
	td=$1; printf 'unchanged\n' > "$td/f"
	"$PROG" unchanged unchanged -i "$td/f" > /dev/null 2>&1
	[ "$(cat "$td/f")" = 'unchanged' ] && echo PASS > "$td/result" || echo "FAIL: expected unchanged got [$(cat "$td/f")]" > "$td/result"
}

t_backup_twice() {
	td=$1; printf 'first\n' > "$td/f"
	"$PROG" first second -i.bak "$td/f" > /dev/null 2>&1
	cmp -s "$td/f.bak" <(printf 'first\n') || { echo "FAIL: first backup corrupted" > "$td/result"; return; }
	printf 'second\n' > "$td/f"
	"$PROG" second third -i.bak2 "$td/f" > /dev/null 2>&1
	cmp -s "$td/f.bak2" <(printf 'second\n') || { echo "FAIL: second backup corrupted" > "$td/result"; return; }
	[ "$(cat "$td/f")" = 'third' ] && echo PASS > "$td/result" || echo "FAIL: final content mismatch" > "$td/result"
}

t_inplace_multi_file_mixed() {
	td=$1
	printf 'aaa\n' > "$td/f1"
	printf 'bbb\n' > "$td/f2"
	printf 'aaa\n' > "$td/f3"
	"$PROG" aaa replaced -i "$td/f1" "$td/f2" "$td/f3" 2>/dev/null
	c1=$(cat "$td/f1"); c2=$(cat "$td/f2"); c3=$(cat "$td/f3")
	[ "$c1" = 'replaced' ] && [ "$c2" = 'bbb' ] && [ "$c3" = 'replaced' ] && echo PASS > "$td/result" || echo "FAIL: f1 [$c1] f2 [$c2] f3 [$c3]" > "$td/result"
}

t_binary_skipped() {
	td=$1
	printf 'abc\x00def' > "$td/f.xyz"
	"$PROG" abc xyz -i "$td/f.xyz" > /dev/null 2>&1
	c=$(tr '\0' '.' < "$td/f.xyz")
	[ "$c" = 'abc.def' ] && echo PASS > "$td/result" || echo "FAIL: expected [abc.def] got [$c]" > "$td/result"
}

t_large_text_file_processed() {
	td=$1
	i=0; : > "$td/f"
	while [ $i -lt 200 ]; do printf 'hello world\n' >> "$td/f"; i=$((i + 1)); done
	[ "$(wc -c < "$td/f")" -gt 1024 ] || { echo "FAIL: fixture too small" > "$td/result"; return; }
	"$PROG" hello goodbye -i -g "$td/f" > /dev/null 2>&1
	left=$(grep -c hello "$td/f")
	[ "$left" = 0 ] && echo PASS > "$td/result" || echo "FAIL: >1KiB text file skipped (hello left: [$left])" > "$td/result"
}

t_binary_nul_past_kib_processed() {
	td=$1
	i=0; : > "$td/f"
	while [ $i -lt 120 ]; do printf 'aaaaaaaa\n' >> "$td/f"; i=$((i + 1)); done
	printf '\x00def\n' >> "$td/f"
	"$PROG" def xyz -i "$td/f" > /dev/null 2>&1
	grep -q xyz "$td/f" && echo PASS > "$td/result" || echo "FAIL: late-NUL file was skipped" > "$td/result"
}

t_stdin_binary_content() {
	td=$1
	printf 'abc\x00def' | "$PROG" abc xyz -g 2>/dev/null > "$td/out"
	printf 'xyz\x00def\n' > "$td/exp"
	cmp -s "$td/out" "$td/exp" && echo PASS > "$td/result" || echo "FAIL: binary content mismatch" > "$td/result"
}

t_non_regular_file() {
	td=$1
	if command -v mkfifo > /dev/null 2>&1; then
		mkfifo "$td/fifo" 2>/dev/null
		rc=0; "$PROG" foo bar -i "$td/fifo" > /dev/null 2>&1 || rc=$?
		[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: FIFO should error" > "$td/result"
	else
		echo PASS > "$td/result"
	fi
}

t_readonly_dir_inplace() {
	td=$1; mkdir "$td/rodir"; printf 'content\n' > "$td/rodir/f"
	chmod 0555 "$td/rodir"
	rc=0; "$PROG" content replaced -i "$td/rodir/f" > /dev/null 2>&1 || rc=$?
	chmod 0755 "$td/rodir"
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: read-only dir in-place should error (rc=$rc)" > "$td/result"
}

t_inplace_readonly_file_nobackup() {
	td=$1; printf 'content\n' > "$td/f"; chmod 0444 "$td/f"
	"$PROG" content replaced -i "$td/f" 2>/dev/null; chmod 0644 "$td/f"
	[ "$(cat "$td/f")" = 'replaced' ] && echo PASS > "$td/result" || echo "FAIL: expected [replaced] got [$(cat "$td/f")]" > "$td/result"
}

t_stdin_large() {
	td=$1; input=$(awk 'BEGIN{for(i=0;i<5000;i++) printf "x"}')
	out=$(printf '%s\n' "$input" | "$PROG" x y -g 2>/dev/null)
	expected=$(awk 'BEGIN{for(i=0;i<5000;i++) printf "y"}')
	[ "$out" = "$expected" ] && echo PASS > "$td/result" || echo "FAIL: large stdin size mismatch (outlen=${#out} explen=${#expected})" > "$td/result"
}

t_stdin_large_regex() {
	td=$1; input=$(awk 'BEGIN{for(i=0;i<5000;i++) printf "x"}')
	out=$(printf '%s\n' "$input" | "$PROG" x y -Rg 2>/dev/null)
	expected=$(awk 'BEGIN{for(i=0;i<5000;i++) printf "y"}')
	[ "$out" = "$expected" ] && echo PASS > "$td/result" || echo "FAIL: large regex size mismatch (outlen=${#out} explen=${#expected})" > "$td/result"
}

t_stdout_multi_file() {
	td=$1; printf 'hello\n' > "$td/f1"; printf 'world\n' > "$td/f2"
	out=$("$PROG" hello hi "$td/f1" "$td/f2" 2>/dev/null)
	[ "$out" = "$(printf 'hi\nworld\n')" ] && echo PASS > "$td/result" || echo "FAIL: expected [hi\nworld\n] got [$out]" > "$td/result"
}

t_long_line() {
	td=$1; long=$(printf '%1000s' | tr ' ' 'a')
	out=$(printf '%s\n' "$long" | "$PROG" xxyyzz 'REPLACED' 2>/dev/null)
	[ "$out" = "$long" ] && echo PASS > "$td/result" || echo "FAIL: long line mismatch" > "$td/result"
}

TESTS="
t_backup_content_identity
t_backup_empty_file
t_backup_binary_content
t_backup_multi_file
t_inplace_shorter
t_inplace_longer
t_inplace_same_length
t_inplace_identical
t_backup_twice
t_inplace_multi_file_mixed
t_binary_skipped
t_large_text_file_processed
t_binary_nul_past_kib_processed
t_stdin_binary_content
t_non_regular_file
t_readonly_dir_inplace
t_inplace_readonly_file_nobackup
t_stdin_large
t_stdin_large_regex
t_stdout_multi_file
t_long_line
"
run_suite "I/O and backup tests" "$TESTS"
