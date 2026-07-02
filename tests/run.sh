#!/bin/sh
# Parallel find-and-replace integration tests

PROG_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROG="$PROG_DIR/find-and-replace"
export LD_LIBRARY_PATH="$PROG_DIR/lib/jstring/build/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
PASS=0
FAIL=0
FAIL_LIST=''

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

td_root=$(mktemp -d)
trap 'rm -rf "$td_root"' EXIT

# Each test function writes outcome to "$1/result"
# Format: PASS or FAIL: <reason>

t_fixed_stdin() {
	td=$1; out=$(echo 'hello world' | "$PROG" hello goodbye 2>/dev/null)
	[ "$out" = 'goodbye world' ] && echo PASS > "$td/result" || echo "FAIL: expected [goodbye world] got [$out]" > "$td/result"
}

t_global() {
	td=$1; out=$(echo 'la la la' | "$PROG" la lu -g 2>/dev/null)
	[ "$out" = 'lu lu lu' ] && echo PASS > "$td/result" || echo "FAIL: expected [lu lu lu] got [$out]" > "$td/result"
}

t_explicit_G() {
	td=$1; out=$(echo 'la la la' | "$PROG" la lu -G 2>/dev/null)
	[ "$out" = 'lu la la' ] && echo PASS > "$td/result" || echo "FAIL: expected [lu la la] got [$out]" > "$td/result"
}

t_inplace() {
	td=$1; printf 'foo bar foo bar\n' > "$td/f"; "$PROG" foo baz -i "$td/f" 2>/dev/null
	content=$(cat "$td/f")
	[ "$content" = 'baz bar foo bar' ] && echo PASS > "$td/result" || echo "FAIL: expected [baz bar foo bar] got [$content]" > "$td/result"
}

t_inplace_backup() {
	td=$1; printf 'replace me\n' > "$td/f"
	"$PROG" me you -i.bak "$td/f" 2>/dev/null
	c=$(cat "$td/f"); b=$(cat "$td/f.bak" 2>/dev/null)
	[ "$c" = 'replace you' ] && [ "$b" = 'replace me' ] && echo PASS > "$td/result" || echo "FAIL: content [$c] backup [$b]" > "$td/result"
}

t_regex() {
	td=$1; out=$(printf 'abc123def\n' | "$PROG" '[0-9][0-9][0-9]' 'NUM' -R 2>/dev/null)
	[ "$out" = 'abcNUMdef' ] && echo PASS > "$td/result" || echo "FAIL: expected [abcNUMdef] got [$out]" > "$td/result"
}

t_ignore_case() {
	td=$1; out=$(printf 'Hello World\n' | "$PROG" hello hi -I 2>/dev/null)
	[ "$out" = 'hi World' ] && echo PASS > "$td/result" || echo "FAIL: expected [hi World] got [$out]" > "$td/result"
}

t_extended_regex() {
	td=$1; out=$(printf 'foo bar baz\n' | "$PROG" '(foo|bar)' 'X' -E 2>/dev/null)
	[ "$out" = 'X bar baz' ] && echo PASS > "$td/result" || echo "FAIL: expected [X bar baz] got [$out]" > "$td/result"
}

t_multi_file() {
	td=$1; printf 'abc\n' > "$td/1"; printf 'abc\n' > "$td/2"
	"$PROG" abc xyz -i "$td/1" "$td/2" 2>/dev/null
	c1=$(cat "$td/1"); c2=$(cat "$td/2")
	[ "$c1" = 'xyz' ] && [ "$c2" = 'xyz' ] && echo PASS > "$td/result" || echo "FAIL: file1 [$c1] file2 [$c2]" > "$td/result"
}

t_recursive() {
	td=$1; mkdir -p "$td/sub"
	printf 'deep\n' > "$td/sub/a.txt"; printf 'deep\n' > "$td/sub/b.c"
	"$PROG" deep shallow -i -r "$td/sub" 2>/dev/null
	t1=$(cat "$td/sub/a.txt"); t2=$(cat "$td/sub/b.c")
	[ "$t1" = 'shallow' ] && [ "$t2" = 'shallow' ] && echo PASS > "$td/result" || echo "FAIL: txt [$t1] c [$t2]" > "$td/result"
}

t_include() {
	td=$1; mkdir -p "$td/sub"
	printf 'aaa\n' > "$td/sub/a.txt"; printf 'bbb\n' > "$td/sub/b.txt"; printf 'aaa\n' > "$td/sub/c.c"
	"$PROG" aaa a_replaced -i -r --include '*.txt' "$td/sub" 2>/dev/null
	ta=$(cat "$td/sub/a.txt"); tb=$(cat "$td/sub/b.txt"); tc=$(cat "$td/sub/c.c")
	[ "$ta" = 'a_replaced' ] && [ "$tb" = 'bbb' ] && [ "$tc" = 'aaa' ] && echo PASS > "$td/result" || echo "FAIL: a [$ta] b [$tb] c [$tc]" > "$td/result"
}

t_exclude() {
	td=$1; mkdir -p "$td/sub"
	printf 'keep\n' > "$td/sub/k.txt"; printf 'ignore\n' > "$td/sub/i.txt"
	"$PROG" keep kept -i --exclude 'i*' "$td/sub/k.txt" "$td/sub/i.txt" 2>/dev/null
	tk=$(cat "$td/sub/k.txt"); ti=$(cat "$td/sub/i.txt")
	[ "$tk" = 'kept' ] && [ "$ti" = 'ignore' ] && echo PASS > "$td/result" || echo "FAIL: keep [$tk] ignore [$ti]" > "$td/result"
}

t_multiline_find() {
	td=$1; out=$(printf 'a\nb\nc' | "$PROG" 'a
b' 'A B' 2>/dev/null)
	printf '%s' "$out" | cmp -s - <(printf 'A B\nc') && echo PASS > "$td/result" || echo "FAIL: got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result"
}

t_tab_escape() {
	td=$1; out=$(printf 'a\tb\n' | "$PROG" '\t' 'TAB' 2>/dev/null)
	[ "$out" = 'aTABb' ] && echo PASS > "$td/result" || echo "FAIL: expected [aTABb] got [$out]" > "$td/result"
}

t_slash() {
	td=$1; out=$(printf 'a/b\n' | "$PROG" '/' '-' 2>/dev/null)
	[ "$out" = 'a-b' ] && echo PASS > "$td/result" || echo "FAIL: expected [a-b] got [$out]" > "$td/result"
}

t_help() {
	td=$1; "$PROG" foo bar -h > /dev/null 2>&1 && echo PASS > "$td/result" || echo "FAIL: -h should exit 0" > "$td/result"
}

t_no_match() {
	td=$1; out=$(printf 'abc\n' | "$PROG" xyz 'X' 2>/dev/null)
	[ "$out" = 'abc' ] && echo PASS > "$td/result" || echo "FAIL: expected [abc] got [$out]" > "$td/result"
}

t_global_regex() {
	td=$1; out=$(printf 'a1b2c3\n' | "$PROG" '[0-9]' 'X' -Rg 2>/dev/null)
	[ "$out" = 'aXbXcX' ] && echo PASS > "$td/result" || echo "FAIL: expected [aXbXcX] got [$out]" > "$td/result"
}

t_empty_replace() {
	td=$1; out=$(printf 'hello\n' | "$PROG" lo '' 2>/dev/null)
	[ "$out" = 'hel' ] && echo PASS > "$td/result" || echo "FAIL: expected [hel] got [$out]" > "$td/result"
}

t_empty_input() {
	td=$1; out=$(printf '' | "$PROG" foo bar 2>/dev/null)
	[ "$out" = '' ] && echo PASS > "$td/result" || echo "FAIL: expected [] got [$out]" > "$td/result"
}

t_find_equals_replace() {
	td=$1; out=$(printf 'abc\n' | "$PROG" abc abc 2>/dev/null)
	[ "$out" = 'abc' ] && echo PASS > "$td/result" || echo "FAIL: expected [abc] got [$out]" > "$td/result"
}

t_case_sensitive() {
	td=$1; out=$(printf 'Hello\n' | "$PROG" hello bye 2>/dev/null)
	[ "$out" = 'Hello' ] && echo PASS > "$td/result" || echo "FAIL: expected [Hello] got [$out]" > "$td/result"
}

t_replace_longer() {
	td=$1; out=$(printf 'ab\n' | "$PROG" ab 'much longer' 2>/dev/null)
	[ "$out" = 'much longer' ] && echo PASS > "$td/result" || echo "FAIL: expected [much longer] got [$out]" > "$td/result"
}

t_overlapping() {
	td=$1; out=$(printf 'aaaa\n' | "$PROG" aa a -g 2>/dev/null)
	[ "$out" = 'aa' ] && echo PASS > "$td/result" || echo "FAIL: expected [aa] got [$out]" > "$td/result"
}

t_stdin_inplace_err() {
	td=$1; rc=0; printf 'test' | "$PROG" test ok -i > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: stdin+in-place should error" > "$td/result"
}

t_stdin_recursive_err() {
	td=$1; rc=0; printf 'test' | "$PROG" test ok -r > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: stdin+recursive should error" > "$td/result"
}

t_nonexistent_file() {
	td=$1; rc=0; "$PROG" foo bar -i "$td/nonexistent" > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: nonexistent file should error" > "$td/result"
}

t_invalid_flag() {
	td=$1; rc=0; printf 'a\n' | "$PROG" a b -X > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: invalid flag should error" > "$td/result"
}

t_no_find() {
	td=$1; rc=0; "$PROG" > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: missing FIND should error" > "$td/result"
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

t_backreference() {
	td=$1; out=$(printf 'abc def\n' | "$PROG" '([a-z]+) ([a-z]+)' '\\2 \\1' -RE 2>/dev/null)
	[ "$out" = 'def abc' ] && echo PASS > "$td/result" || echo "FAIL: expected [def abc] got [$out]" > "$td/result"
}

t_binary_skipped() {
	td=$1
	printf 'abc\x00def' > "$td/f.xyz"

	"$PROG" abc xyz -i "$td/f.xyz" > /dev/null 2>&1

	c=$(tr '\0' '.' < "$td/f.xyz")
	[ "$c" = 'abc.def' ] \
		&& echo PASS > "$td/result" \
		|| echo "FAIL: expected [abc.def] got [$c]" > "$td/result"
}

t_long_line() {
	td=$1; long=$(printf '%1000s' | tr ' ' 'a')
	out=$(printf '%s\n' "$long" | "$PROG" xxyyzz 'REPLACED' 2>/dev/null)
	[ "$out" = "$long" ] && echo PASS > "$td/result" || echo "FAIL: long line mismatch" > "$td/result"
}

t_explicit_F() {
	td=$1; out=$(printf 'hello world\n' | "$PROG" hello goodbye -F 2>/dev/null)
	[ "$out" = 'goodbye world' ] && echo PASS > "$td/result" || echo "FAIL: expected [goodbye world] got [$out]" > "$td/result"
}

t_Z_flag() {
	td=$1; out=$(printf 'a\nb\n' | "$PROG" '^b' 'B' -RZ 2>/dev/null)
	# With -Z (REG_NEWLINE, default), ^ matches after newline → b replaced with B
	# Output should be a\nB (possibly with trailing newline)
	case "$out" in
		"$(printf 'a\nB')"|"$(printf 'a\nB\n')") echo PASS > "$td/result" ;;
		*) echo "FAIL: Z flag expected [a.B] got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result" ;;
	esac
}

t_z_flag() {
	td=$1; out=$(printf 'a\nb\n' | "$PROG" '^b' 'B' -Rz 2>/dev/null)
	# With -z (no REG_NEWLINE), ^ only matches string start → b unchanged
	[ "$out" = "$(printf 'a\nb\n')" ] || [ "$out" = "$(printf 'a\nb')" ] && echo PASS > "$td/result" || echo "FAIL: z flag, expected unchanged [a.b.] got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result"
}

t_global_then_G() {
	td=$1; out=$(printf 'la la la\n' | "$PROG" la lu -Gg 2>/dev/null)
	[ "$out" = 'lu lu lu' ] && echo PASS > "$td/result" || echo "FAIL: expected [lu lu lu] got [$out]" > "$td/result"
}

t_G_then_global() {
	td=$1; out=$(printf 'la la la\n' | "$PROG" la lu -gG 2>/dev/null)
	[ "$out" = 'lu la la' ] && echo PASS > "$td/result" || echo "FAIL: expected [lu la la] got [$out]" > "$td/result"
}

t_inplace_no_change() {
	td=$1; printf 'no match here\n' > "$td/f"; "$PROG" xyzzy REPLACED -i "$td/f" 2>/dev/null
	content=$(cat "$td/f")
	[ "$content" = 'no match here' ] && echo PASS > "$td/result" || echo "FAIL: expected unchanged file got [$content]" > "$td/result"
}

t_combined_i_r() {
	td=$1; printf 'hello\n' > "$td/f"; "$PROG" hello hi -ir "$td/f" 2>/dev/null
	# -ir treats 'r' as the backup suffix, not --recursive flag
	bak=$(cat "$td/fr" 2>/dev/null); orig=$(cat "$td/f" 2>/dev/null)
	[ "$orig" = 'hi' ] && [ "$bak" = 'hello' ] && echo PASS > "$td/result" || echo "FAIL: orig [$orig] bak [$bak]" > "$td/result"
}

t_end_of_options() {
	td=$1; printf 'match\n' > "$td/f.txt"; printf 'match\n' > "$td/f.c"
	# --exclude should be skipped in the file pass; only .c file should be processed
	"$PROG" match replaced -i --exclude '*.txt' "$td/f.txt" "$td/f.c" 2>/dev/null
	ct=$(cat "$td/f.txt"); cc=$(cat "$td/f.c")
	[ "$ct" = 'match' ] && [ "$cc" = 'replaced' ] && echo PASS > "$td/result" || echo "FAIL: txt [$ct] c [$cc]" > "$td/result"
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

t_no_args() {
	td=$1; rc=0; "$PROG" > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: no args should exit non-zero" > "$td/result"
}

t_missing_replace() {
	td=$1; rc=0; "$PROG" find > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: missing REPLACE should exit non-zero" > "$td/result"
}

t_recursive_exclude() {
	td=$1; mkdir -p "$td/sub"
	printf 'keep\n' > "$td/sub/k.txt"; printf 'skip\n' > "$td/sub/skip.me"
	"$PROG" keep kept -i -r --exclude '*.me' "$td/sub" 2>/dev/null
	tk=$(cat "$td/sub/k.txt"); ts=$(cat "$td/sub/skip.me")
	[ "$tk" = 'kept' ] && [ "$ts" = 'skip' ] && echo PASS > "$td/result" || echo "FAIL: keep [$tk] skip [$ts]" > "$td/result"
}

t_include_exclude_combined() {
	td=$1; mkdir -p "$td/sub"
	printf 'aaa\n' > "$td/sub/a.txt"; printf 'bbb\n' > "$td/sub/b.txt"; printf 'ccc\n' > "$td/sub/c.c"
	"$PROG" aaa REPLACED -i -r --include '*.txt' --exclude 'b*' "$td/sub" 2>/dev/null
	ta=$(cat "$td/sub/a.txt"); tb=$(cat "$td/sub/b.txt"); tc=$(cat "$td/sub/c.c")
	[ "$ta" = 'REPLACED' ] && [ "$tb" = 'bbb' ] && [ "$tc" = 'ccc' ] && echo PASS > "$td/result" || echo "FAIL: a [$ta] b [$tb] c [$tc]" > "$td/result"
}

t_exclude_on_cli_files() {
	td=$1; printf 'aaa\n' > "$td/a.txt"; printf 'aaa\n' > "$td/b.c"
	"$PROG" aaa REPLACED -i --exclude '*.txt' "$td/a.txt" "$td/b.c" 2>/dev/null
	ta=$(cat "$td/a.txt"); tb=$(cat "$td/b.c")
	# a.txt excluded by --exclude, b.c should be processed
	[ "$ta" = 'aaa' ] && [ "$tb" = 'REPLACED' ] && echo PASS > "$td/result" || echo "FAIL: a [$ta] b [$tb]" > "$td/result"
}

t_multi_directory_recursive() {
	td=$1; mkdir -p "$td/d1" "$td/d2"
	printf 'hello\n' > "$td/d1/a.txt"; printf 'world\n' > "$td/d2/b.txt"
	"$PROG" hello hi -i -r "$td/d1" "$td/d2" 2>/dev/null
	ca=$(cat "$td/d1/a.txt"); cb=$(cat "$td/d2/b.txt")
	[ "$ca" = 'hi' ] && [ "$cb" = 'world' ] && echo PASS > "$td/result" || echo "FAIL: d1 [$ca] d2 [$cb]" > "$td/result"
}

t_regex_basic_no_backref() {
	td=$1; out=$(printf 'abc123def\n' | "$PROG" '[a-z]*[0-9][0-9]*[a-z]*' 'NUM' -R 2>/dev/null)
	[ "$out" = 'NUM' ] && echo PASS > "$td/result" || echo "FAIL: expected [NUM] got [$out]" > "$td/result"
}

t_include_without_arg() {
	td=$1; rc=0; "$PROG" foo bar --include > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: --include without arg should exit non-zero" > "$td/result"
}

t_exclude_without_arg() {
	td=$1; rc=0; "$PROG" foo bar --exclude > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: --exclude without arg should exit non-zero" > "$td/result"
}

t_inplace_backup_collision() {
	td=$1; printf 'original\n' > "$td/f"; printf 'collision\n' > "$td/f.bak"
	rc=0; "$PROG" original replaced -i.bak "$td/f" > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: should error when backup file exists (rc=$rc)" > "$td/result"
}

t_z_with_regex() {
	td=$1; out=$(printf 'hello\nworld\n' | "$PROG" 'hello$' 'HI' -Rz 2>/dev/null)
	# With -z (no REG_NEWLINE), $ matches end of string only; hello not at end → no match
	case "$out" in
		"$(printf 'hello\nworld')"|"$(printf 'hello\nworld\n')") echo PASS > "$td/result" ;;
		*) echo "FAIL: z+regex expected unchanged got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result" ;;
	esac
}

t_Z_with_regex() {
	td=$1; out=$(printf 'hello\nworld\n' | "$PROG" 'hello$' 'HI' -RZ 2>/dev/null)
	# With -Z (REG_NEWLINE, default), $ matches before newline → hello replaced with HI
	case "$out" in
		"$(printf 'HI\nworld')"|"$(printf 'HI\nworld\n')") echo PASS > "$td/result" ;;
		*) echo "FAIL: Z+regex expected HI.world got [$(printf '%s' "$out" | tr '\n' '.')]" > "$td/result" ;;
	esac
}

printf '\n=== find-and-replace tests ===\n\n'

# List all test functions here
TESTS="
t_fixed_stdin
t_global
t_explicit_G
t_inplace
t_inplace_backup
t_regex
t_ignore_case
t_extended_regex
t_multi_file
t_recursive
t_include
t_exclude
t_multiline_find
t_tab_escape
t_slash
t_help
t_no_match
t_global_regex
t_empty_replace
t_empty_input
t_find_equals_replace
t_case_sensitive
t_replace_longer
t_overlapping
t_stdin_inplace_err
t_stdin_recursive_err
t_nonexistent_file
t_invalid_flag
t_no_find
t_octal_escape
t_newlines_in_replace
t_backreference
t_long_line
t_explicit_F
t_Z_flag
t_z_flag
t_global_then_G
t_G_then_global
t_inplace_no_change
t_combined_i_r
t_end_of_options
t_escape_ff
t_escape_cr
t_escape_vt
t_escape_bs
t_no_args
t_missing_replace
t_recursive_exclude
t_include_exclude_combined
t_exclude_on_cli_files
t_multi_directory_recursive
t_regex_basic_no_backref
t_include_without_arg
t_exclude_without_arg
t_inplace_backup_collision
t_z_with_regex
t_Z_with_regex
"

# Launch all tests in parallel
for t in $TESTS; do
	(
		mkdir -p "$td_root/$t"
		"$t" "$td_root/$t"
	) &
done
wait

# Collect results in order
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
