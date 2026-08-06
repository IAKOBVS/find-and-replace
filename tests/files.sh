#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

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

t_include_and_exclude_same_glob() {
	td=$1; mkdir -p "$td/sub"
	printf 'aaa\n' > "$td/sub/a.txt"; printf 'aaa\n' > "$td/sub/b.txt"
	"$PROG" aaa REPLACED -i -r --include '*.txt' --exclude '*.txt' "$td/sub" 2>/dev/null
	ca=$(cat "$td/sub/a.txt"); cb=$(cat "$td/sub/b.txt")
	[ "$ca" = 'aaa' ] && [ "$cb" = 'aaa' ] && echo PASS > "$td/result" || echo "FAIL: a [$ca] b [$cb]" > "$td/result"
}

t_include_glob_no_match() {
	td=$1; mkdir -p "$td/sub"
	printf 'aaa\n' > "$td/sub/a.txt"; printf 'bbb\n' > "$td/sub/b.c"
	"$PROG" aaa replaced -i -r --include '*.xyz' "$td/sub" 2>/dev/null
	ta=$(cat "$td/sub/a.txt"); tb=$(cat "$td/sub/b.c")
	[ "$ta" = 'aaa' ] && [ "$tb" = 'bbb' ] && echo PASS > "$td/result" || echo "FAIL: a.txt [$ta] b.c [$tb]" > "$td/result"
}

t_exclude_on_cli_files() {
	td=$1; printf 'aaa\n' > "$td/a.txt"; printf 'aaa\n' > "$td/b.c"
	"$PROG" aaa REPLACED -i --exclude '*.txt' "$td/a.txt" "$td/b.c" 2>/dev/null
	ta=$(cat "$td/a.txt"); tb=$(cat "$td/b.c")
	[ "$ta" = 'aaa' ] && [ "$tb" = 'REPLACED' ] && echo PASS > "$td/result" || echo "FAIL: a [$ta] b [$tb]" > "$td/result"
}

t_multi_directory_recursive() {
	td=$1; mkdir -p "$td/d1" "$td/d2"
	printf 'hello\n' > "$td/d1/a.txt"; printf 'world\n' > "$td/d2/b.txt"
	"$PROG" hello hi -i -r "$td/d1" "$td/d2" 2>/dev/null
	ca=$(cat "$td/d1/a.txt"); cb=$(cat "$td/d2/b.txt")
	[ "$ca" = 'hi' ] && [ "$cb" = 'world' ] && echo PASS > "$td/result" || echo "FAIL: d1 [$ca] d2 [$cb]" > "$td/result"
}

t_multiple_directories_no_recursion() {
	td=$1; mkdir -p "$td/d1" "$td/d2"
	printf 'aaa\n' > "$td/d1/f"; printf 'bbb\n' > "$td/d2/f"
	"$PROG" aaa replaced "$td/d1" "$td/d2" > /dev/null 2>&1
	ca=$(cat "$td/d1/f"); cb=$(cat "$td/d2/f")
	[ "$ca" = 'aaa' ] && [ "$cb" = 'bbb' ] && echo PASS > "$td/result" || echo "FAIL: expected unchanged files got d1=[$ca] d2=[$cb]" > "$td/result"
}

t_recursive_deep() {
	td=$1; dir="$td/deep"
	mkdir -p "$dir/a/b/c/d/e/f/g/h"
	printf 'findme\n' > "$dir/a/b/c/d/e/f/g/h/target.txt"
	"$PROG" findme found -i -r "$dir" > /dev/null 2>&1
	[ "$(cat "$dir/a/b/c/d/e/f/g/h/target.txt")" = 'found' ] && echo PASS > "$td/result" || echo "FAIL: deep recursion failed" > "$td/result"
}

t_recursive_many_files() {
	td=$1
	for n in $(seq 1 50); do
		printf 'content\n' > "$td/file$n.txt"
	done
	"$PROG" content replaced -i "$td/file"*.txt > /dev/null 2>&1
	allok=1
	for n in $(seq 1 50); do
		[ "$(cat "$td/file$n.txt")" = 'replaced' ] || allok=0
	done
	[ "$allok" -eq 1 ] && echo PASS > "$td/result" || echo "FAIL: not all 50 files replaced" > "$td/result"
}

t_recursive_on_regular_file() {
	td=$1; printf 'findme\n' > "$td/f"
	out=$("$PROG" findme found -r "$td/f" 2>/dev/null)
	[ "$out" = 'found' ] && echo PASS > "$td/result" || echo "FAIL: -r on regular file expected [found] got [$out]" > "$td/result"
}

t_recursive_nonexistent_dir() {
	td=$1; rc=0; "$PROG" foo bar -r "$td/nope" > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: -r on nonexistent dir should error (rc=$rc)" > "$td/result"
}

t_recursive_empty_dir() {
	td=$1; mkdir -p "$td/sub"
	"$PROG" foo bar -i -r "$td/sub" 2>/dev/null
	[ $? -eq 0 ] && echo PASS > "$td/result" || echo "FAIL: empty dir recursion should exit 0" > "$td/result"
}

t_recursive_partial_fail() {
	td=$1; mkdir -p "$td/sub1" "$td/sub2"
	printf 'aaa\n' > "$td/sub1/f"
	rc=0; "$PROG" aaa bbb -i -r "$td/sub1" "$td/sub2/nonexistent" > /dev/null 2>&1 || rc=$?
	content=$(cat "$td/sub1/f")
	[ "$rc" -ne 0 ] && [ "$content" = 'bbb' ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc content=[$content]" > "$td/result"
}

t_double_dash_include_recursive() {
	td=$1; mkdir -p "$td/sub"
	printf 'match\n' > "$td/sub/a.txt"
	printf 'match\n' > "$td/sub/b.c"
	"$PROG" match replaced -i -r --include '*.txt' "$td/sub" 2>/dev/null
	txt=$(cat "$td/sub/a.txt" 2>/dev/null)
	c=$(cat "$td/sub/b.c" 2>/dev/null)
	[ "$txt" = 'replaced' ] && [ "$c" = 'match' ] && echo PASS > "$td/result" || echo "FAIL: txt [$txt] c [$c]" > "$td/result"
}

t_recursive_include_exclude_dash_fname() {
	td=$1; mkdir -p "$td/sub"
	printf 'findme\n' > "$td/sub/-f.txt"
	printf 'findme\n' > "$td/sub/g.txt"
	"$PROG" findme found -i -r --include '*.txt' --exclude '-*' "$td/sub" 2>/dev/null
	f=$(cat "$td/sub/-f.txt" 2>/dev/null)
	g=$(cat "$td/sub/g.txt" 2>/dev/null)
	[ "$f" = 'findme' ] && [ "$g" = 'found' ] && echo PASS > "$td/result" || echo "FAIL: -f [$f] g [$g]" > "$td/result"
}

t_include_cli_file_noop() {
	td=$1; printf 'aaa\n' > "$td/f.txt"
	"$PROG" aaa replaced -i --include '*.txt' "$td/f.txt" 2>/dev/null
	[ "$(cat "$td/f.txt")" = 'replaced' ] && echo PASS > "$td/result" || echo "FAIL: --include on CLI file should be no-op, expected [replaced] got [$(cat "$td/f.txt")]" > "$td/result"
}

t_recursive_to_stdout() {
	td=$1; mkdir -p "$td/sub"
	printf 'deep\n' > "$td/sub/a.txt"
	out=$("$PROG" deep shallow -r "$td/sub" 2>/dev/null)
	[ "$out" = 'shallow' ] && echo PASS > "$td/result" || echo "FAIL: expected [shallow] got [$out]" > "$td/result"
}

t_dash_filename_no_double_dash() {
	td=$1; printf 'match\n' > "$td/-f"
	out=$("$PROG" match replaced < "$td/-f" 2>/dev/null)
	[ "$out" = 'replaced' ] && echo PASS > "$td/result" || echo "FAIL: expected [replaced] got [$out]" > "$td/result"
}

TESTS="
t_multi_file
t_recursive
t_include
t_exclude
t_recursive_exclude
t_include_exclude_combined
t_include_and_exclude_same_glob
t_include_glob_no_match
t_exclude_on_cli_files
t_multi_directory_recursive
t_multiple_directories_no_recursion
t_recursive_deep
t_recursive_many_files
t_recursive_on_regular_file
t_recursive_nonexistent_dir
t_recursive_empty_dir
t_recursive_partial_fail
t_double_dash_include_recursive
t_recursive_include_exclude_dash_fname
t_include_cli_file_noop
t_recursive_to_stdout
t_dash_filename_no_double_dash
"
run_suite "file operation tests" "$TESTS"
