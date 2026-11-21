#!/bin/sh
PROG_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$PROG_DIR/tests/lib.sh"
TEST_BIN_DIR=${PIPELINE_TEST_BIN_DIR:-"$PROG_DIR/tests/pipeline"}

t_pipeline_spsc_unit() {
	td=$1
	if [ ! -x "$TEST_BIN_DIR/spsc_unit" ]; then
		echo "FAIL: tests/pipeline/spsc_unit missing (run make)" > "$td/result"
		return
	fi
	if "$TEST_BIN_DIR/spsc_unit" > "$td/out" 2>&1; then
		echo PASS > "$td/result"
	else
		echo "FAIL: spsc unit: $(cat "$td/out")" > "$td/result"
	fi
}

t_pipeline_spmc_unit() {
	td=$1
	if [ ! -x "$TEST_BIN_DIR/spmc_unit" ]; then
		echo "FAIL: tests/pipeline/spmc_unit missing (run make)" > "$td/result"
		return
	fi
	if "$TEST_BIN_DIR/spmc_unit" > "$td/out" 2>&1; then
		echo PASS > "$td/result"
	else
		echo "FAIL: spmc unit: $(cat "$td/out")" > "$td/result"
	fi
}

t_pipeline_multi_worker_inplace() {
	td=$1; mkdir -p "$td/sub"
	for i in $(seq 1 200); do printf 'foo\n' > "$td/sub/f$i"; done
	"$PROG" foo bar -i -r -j 4 "$td/sub" 2>/dev/null
	bad=0
	for f in "$td"/sub/f*; do
		[ "$(cat "$f")" = 'bar' ] || bad=$((bad + 1))
	done
	[ "$bad" -eq 0 ] && echo PASS > "$td/result" || echo "FAIL: $bad files not replaced" > "$td/result"
}

t_pipeline_multi_worker_explicit_batch() {
	td=$1; mkdir -p "$td/sub"
	for i in $(seq 1 100); do printf 'foo\n' > "$td/sub/f$i"; done
	set -- "$td"/sub/f*
	"$PROG" foo bar -i -j 4 "$@" 2>/dev/null
	bad=0
	for f in "$td"/sub/f*; do
		[ "$(cat "$f")" = 'bar' ] || bad=$((bad + 1))
	done
	[ "$bad" -eq 0 ] && echo PASS > "$td/result" || echo "FAIL: $bad explicit files not replaced" > "$td/result"
}

t_pipeline_multi_worker_grep() {
	td=$1; mkdir -p "$td/sub"
	for i in $(seq 1 100); do printf 'hit %s\n' "$i" > "$td/sub/f$i"; done
	n=$("$PROG" hit x --grep -r -j 4 "$td/sub" 2>/dev/null | wc -l)
	[ "$n" -eq 100 ] && echo PASS > "$td/result" || echo "FAIL: got $n grep lines" > "$td/result"
}

t_pipeline_j_invalid() {
	td=$1
	rc=0; "$PROG" a b -j 0 < /dev/null > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: -j 0 accepted" > "$td/result"
}

t_pipeline_skips_temp_files() {
	td=$1; mkdir -p "$td/sub"
	printf 'foo\n' > "$td/sub/f"
	printf 'foo\n' > "$td/sub/f.far_tmp_abc123"
	rc=0; "$PROG" foo bar -i -r -j 12 "$td/sub" > /dev/null 2>&1 || rc=$?
	a=$(cat "$td/sub/f"); tmp=$(cat "$td/sub/f.far_tmp_abc123")
	[ "$rc" -eq 0 ] && [ "$a" = 'bar' ] && [ "$tmp" = 'foo' ] && \
		echo PASS > "$td/result" || echo "FAIL: rc=$rc a=[$a] tmp=[$tmp]" > "$td/result"
}

t_pipeline_multi_root_order() {
	td=$1; mkdir -p "$td/r1" "$td/r2"
	printf 'x1\n' > "$td/r1/a"
	printf 'x2\n' > "$td/r2/b"
	out=$("$PROG" x y -r "$td/r1" "$td/r2" 2>/dev/null)
	exp='y1
y2'
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: out=[$out] exp=[$exp]" > "$td/result"
}

t_pipeline_recursive_inplace() {
	td=$1; mkdir -p "$td/sub/deep"
	printf 'foo\n' > "$td/sub/a"
	printf 'foo\n' > "$td/sub/bb"
	printf 'foo\n' > "$td/sub/deep/ccc"
	"$PROG" foo bar -i -r "$td/sub" 2>/dev/null
	a=$(cat "$td/sub/a"); b=$(cat "$td/sub/bb"); c=$(cat "$td/sub/deep/ccc")
	[ "$a" = 'bar' ] && [ "$b" = 'bar' ] && [ "$c" = 'bar' ] && echo PASS > "$td/result" || echo "FAIL: a[$a] b[$b] c[$c]" > "$td/result"
}

t_pipeline_recursive_backup() {
	td=$1; mkdir -p "$td/sub"
	printf 'old\n' > "$td/sub/a"
	printf 'old\n' > "$td/sub/b"
	"$PROG" old new -i.bak -r "$td/sub" 2>/dev/null
	a=$(cat "$td/sub/a"); ab=$(cat "$td/sub/a.bak")
	b=$(cat "$td/sub/b"); bb=$(cat "$td/sub/b.bak")
	[ "$a" = 'new' ] && [ "$ab" = 'old' ] && [ "$b" = 'new' ] && [ "$bb" = 'old' ] && echo PASS > "$td/result" || echo "FAIL: a[$a/$ab] b[$b/$bb]" > "$td/result"
}

t_pipeline_recursive_global() {
	td=$1; mkdir -p "$td/sub"
	printf 'la la la\n' > "$td/sub/a"
	out=$("$PROG" la lu -g -r "$td/sub" 2>/dev/null)
	[ "$out" = 'lu lu lu' ] && echo PASS > "$td/result" || echo "FAIL: expected [lu lu lu] got [$out]" > "$td/result"
}

t_pipeline_include_exclude() {
	td=$1; mkdir -p "$td/sub"
	printf 'match\n' > "$td/sub/a.txt"
	printf 'match\n' > "$td/sub/b.txt"
	printf 'match\n' > "$td/sub/skip.log"
	"$PROG" match replaced -i -r --include '\.txt$' --exclude '^b' "$td/sub" 2>/dev/null
	a=$(cat "$td/sub/a.txt"); b=$(cat "$td/sub/b.txt"); c=$(cat "$td/sub/skip.log")
	[ "$a" = 'replaced' ] && [ "$b" = 'match' ] && [ "$c" = 'match' ] && echo PASS > "$td/result" || echo "FAIL: a[$a] b[$b] log[$c]" > "$td/result"
}

t_pipeline_partial_fail() {
	td=$1; mkdir -p "$td/sub1" "$td/sub2"
	printf 'aaa\n' > "$td/sub1/f"
	rc=0; "$PROG" aaa bbb -i -r "$td/sub1" "$td/sub2/nonexistent" > /dev/null 2>&1 || rc=$?
	content=$(cat "$td/sub1/f")
	[ "$rc" -ne 0 ] && [ "$content" = 'bbb' ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc content=[$content]" > "$td/result"
}

t_pipeline_continues_on_error() {
	td=$1; mkdir -p "$td/sub"
	printf 'old\n' > "$td/sub/a"
	printf 'old\n' > "$td/sub/b"
	chmod 000 "$td/sub/b"
	printf 'old\n' > "$td/sub/c"
	rc=0; "$PROG" old new -i -r "$td/sub" > /dev/null 2> "$td/err" || rc=$?
	ca=$(cat "$td/sub/a"); cb=$(cat "$td/sub/b" 2>/dev/null); cc=$(cat "$td/sub/c")
	err=$(cat "$td/err")
	case "$err" in
		*"file(s) failed during processing"*) msg=1 ;;
		*) msg=0 ;;
	esac
	chmod 644 "$td/sub/b"
	[ "$rc" -ne 0 ] && [ "$ca" = 'new' ] && [ "$cb" != 'new' ] && [ "$cc" = 'new' ] && [ "$msg" -eq 1 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc a[$ca] b[$cb] c[$cc] msg=$msg" > "$td/result"
}

t_pipeline_many_files() {
	td=$1; mkdir -p "$td/sub"
	i=0
	while [ "$i" -lt 200 ]; do
		printf 'bulk\n' > "$td/sub/f$i"
		i=$((i + 1))
	done
	"$PROG" bulk done -i -r "$td/sub" 2>/dev/null
	bad=0
	i=0
	while [ "$i" -lt 200 ]; do
		[ "$(cat "$td/sub/f$i")" = 'done' ] || bad=$((bad + 1))
		i=$((i + 1))
	done
	[ "$bad" -eq 0 ] && echo PASS > "$td/result" || echo "FAIL: $bad of 200 files not replaced" > "$td/result"
}

t_pipeline_grep_multi_root() {
	td=$1; mkdir -p "$td/r1" "$td/r2"
	printf 'hit one\n' > "$td/r1/a"
	printf 'hit two\n' > "$td/r2/b"
	"$PROG" hit hit --grep -r "$td/r1" "$td/r2" > "$td/out" 2>/dev/null
	rc=$?
	out=$(strip_ansi < "$td/out")
	case "$out" in
		*"a:1:hit one"*"b:1:hit two"*) order=1 ;;
		*) order=0 ;;
	esac
	[ "$rc" -eq 0 ] && [ "$order" -eq 1 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out]" > "$td/result"
}

t_pipeline_grep_no_match() {
	td=$1; mkdir -p "$td/sub"
	printf 'abc\n' > "$td/sub/a"
	rc=0; "$PROG" zzz zzz --grep -r "$td/sub" > /dev/null 2>&1 || rc=$?
	[ "$rc" -eq 1 ] && echo PASS > "$td/result" || echo "FAIL: expected rc=1 got $rc" > "$td/result"
}

t_pipeline_flag_between_roots() {
	td=$1; mkdir -p "$td/r1" "$td/r2"
	printf 'a1\n' > "$td/r1/a"
	printf 'a[0-9]\n' > "$td/r2/b"
	out=$("$PROG" 'a[0-9]' X -R -r "$td/r1" -F -r "$td/r2" 2>/dev/null)
	exp='X
X'
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: out=[$out] exp=[$exp]" > "$td/result"
}

t_pipeline_confirm_abort_on_read_error() {
	td=$1; mkdir -p "$td/sub"
	i=0
	while [ "$i" -lt 600 ]; do
		printf 'old\n' > "$td/sub/f$i"
		chmod 000 "$td/sub/f$i"
		i=$((i + 1))
	done
	"$PROG_DIR/tests/pty_drive" --prog "$PROG" --out "$td/out" --rc "$td/rc" --noready --timeout 30 -- old new -c -i -r "$td/sub" >/dev/null 2>&1
	rc=$(cat "$td/rc" 2>/dev/null)
	chmod -R u+rwX "$td/sub"
	case "$rc" in
		''|0|timeout|sig:*) ok=0 ;;
		*) ok=1 ;;
	esac
	[ "$ok" -eq 1 ] && echo PASS > "$td/result" || echo "FAIL: expected non-zero exit, rc=[$rc]" > "$td/result"
}

t_pipeline_stdout_write_error() {
	td=$1; mkdir -p "$td/sub"
	printf 'old\n' > "$td/sub/a"
	rc=0; stdbuf -o0 "$PROG" old new -r "$td/sub" > /dev/full 2>/dev/null || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: stdout write error should exit nonzero (rc=$rc)" > "$td/result"
}

t_pipeline_stderr_write_error() {
	td=$1; mkdir -p "$td/sub"
	printf 'old\n' > "$td/sub/a"
	rc=0; "$PROG" old new -i -r "$td/sub" > /dev/null 2> /dev/full || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: stderr write error should exit nonzero (rc=$rc)" > "$td/result"
}

t_pipeline_l_write_error() {
	td=$1; mkdir -p "$td/sub"
	printf 'old\n' > "$td/sub/a"
	rc=0; stdbuf -o0 "$PROG" old new -i -l -r "$td/sub" > /dev/full 2>/dev/null || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: -l write error should exit nonzero (rc=$rc)" > "$td/result"
}

t_pipeline_lifecycle_unit() {
	td=$1
	if [ ! -x "$TEST_BIN_DIR/pipeline_unit" ]; then
		echo "FAIL: tests/pipeline/pipeline_unit missing (run make)" > "$td/result"
		return
	fi
	if "$TEST_BIN_DIR/pipeline_unit" > "$td/out" 2>&1; then
		echo PASS > "$td/result"
	else
		echo "FAIL: pipeline unit: $(cat "$td/out")" > "$td/result"
	fi
}

t_pipeline_find_longer_than_file() {
	td=$1; mkdir -p "$td/sub"
	printf 'a\n' > "$td/sub/f"
	out=$("$PROG" 'longer-than-the-file' x -r "$td/sub" 2>/dev/null)
	[ -z "$out" ] && echo PASS > "$td/result" || echo "FAIL: expected no output got [$out]" > "$td/result"
}

t_pipeline_binary_skip() {
	td=$1; mkdir -p "$td/sub"
	printf 'a\000b\n' > "$td/sub/f"
	out=$("$PROG" a x -r "$td/sub" 2>/dev/null)
	[ -z "$out" ] && echo PASS > "$td/result" || echo "FAIL: binary file should be skipped, got [$out]" > "$td/result"
}

t_pipeline_grep_regex_recursive() {
	td=$1; mkdir -p "$td/sub"
	printf 'abc\nxyz\n' > "$td/sub/f"
	"$PROG" 'a.c' X --grep -R -r "$td/sub" > "$td/out" 2>/dev/null
	rc=$?
	out=$(strip_ansi < "$td/out")
	case "$out" in
		*"f:1:abc"*) hit=1 ;;
		*) hit=0 ;;
	esac
	[ "$rc" -eq 0 ] && [ "$hit" -eq 1 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out]" > "$td/result"
}

t_pipeline_grep_empty_find_recursive() {
	td=$1; mkdir -p "$td/sub"
	printf 'abc\n' > "$td/sub/f"
	"$PROG" '' X --grep -r "$td/sub" > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 0 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc size=$(wc -c < "$td/out")" > "$td/result"
}

t_pipeline_confirm_abort_sequential() {
	td=$1; mkdir -p "$td/sub"
	printf 'old\n' > "$td/sub/a"
	printf 'old\n' > "$td/sub/b"
	chmod 000 "$td/sub/b"
	rc=0; printf 'y\n' | "$PROG" old new -c -i -r "$td/sub" > /dev/null 2>&1 || rc=$?
	chmod 644 "$td/sub/b"
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: non-tty -c abort should exit nonzero (rc=$rc)" > "$td/result"
}

t_pipeline_grep_stdout_error() {
	td=$1; mkdir -p "$td/sub"
	printf 'hit\n' > "$td/sub/f"
	rc=0; stdbuf -o0 "$PROG" hit x --grep -r "$td/sub" > /dev/full 2>/dev/null || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: grep stdout error should exit nonzero (rc=$rc)" > "$td/result"
}

t_pipeline_sequential_stdout_error() {
	td=$1; printf 'old\n' > "$td/f"
	rc=0; stdbuf -o0 "$PROG" old new "$td/f" > /dev/full 2>/dev/null || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: sequential stdout error should exit nonzero (rc=$rc)" > "$td/result"
}

t_pipeline_sequential_l_error() {
	td=$1; printf 'old\n' > "$td/f"
	rc=0; stdbuf -o0 "$PROG" old new -i -l "$td/f" > /dev/full 2>/dev/null || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: sequential -l error should exit nonzero (rc=$rc)" > "$td/result"
}

t_pipeline_prompt_write_error() {
	td=$1; printf 'old\n' > "$td/f"
	rc=0; printf 'y\n' | stdbuf -o0 "$PROG" old new -c -i "$td/f" > /dev/full 2> "$td/err" || rc=$?
	case "$(cat "$td/err")" in
		*"write error on prompt"*) msg=1 ;;
		*) msg=0 ;;
	esac
	[ "$rc" -ne 0 ] && [ "$msg" -eq 1 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc msg=$msg" > "$td/result"
}

t_pipeline_prompt_flush_error() {
	td=$1; printf 'old\n' > "$td/f"
	rc=0; printf 'y\n' | "$PROG" old new -c -i "$td/f" > /dev/full 2> "$td/err" || rc=$?
	case "$(cat "$td/err")" in
		*"flush error on prompt"*) msg=1 ;;
		*) msg=0 ;;
	esac
	[ "$rc" -ne 0 ] && [ "$msg" -eq 1 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc msg=$msg" > "$td/result"
}

t_pipeline_confirm_noninteractive() {
	td=$1; mkdir -p "$td/sub"
	printf 'old\n' > "$td/sub/a"
	printf 'old\n' > "$td/sub/b"
	printf 'y\n' | "$PROG" old new -c -i -r "$td/sub" > /dev/null 2>&1
	a=$(cat "$td/sub/a"); b=$(cat "$td/sub/b")
	[ "$a" = 'new' ] && [ "$b" = 'new' ] && echo PASS > "$td/result" || echo "FAIL: a[$a] b[$b]" > "$td/result"
}

TESTS="
t_pipeline_spsc_unit
t_pipeline_spmc_unit
t_pipeline_multi_worker_inplace
t_pipeline_multi_worker_explicit_batch
t_pipeline_multi_worker_grep
t_pipeline_skips_temp_files
t_pipeline_j_invalid
t_pipeline_multi_root_order
t_pipeline_recursive_inplace
t_pipeline_recursive_backup
t_pipeline_recursive_global
t_pipeline_include_exclude
t_pipeline_partial_fail
t_pipeline_continues_on_error
t_pipeline_many_files
t_pipeline_grep_multi_root
t_pipeline_grep_no_match
t_pipeline_flag_between_roots
t_pipeline_confirm_abort_on_read_error
t_pipeline_stdout_write_error
t_pipeline_stderr_write_error
t_pipeline_l_write_error
t_pipeline_lifecycle_unit
t_pipeline_find_longer_than_file
t_pipeline_binary_skip
t_pipeline_grep_regex_recursive
t_pipeline_grep_empty_find_recursive
t_pipeline_confirm_abort_sequential
t_pipeline_grep_stdout_error
t_pipeline_sequential_stdout_error
t_pipeline_sequential_l_error
t_pipeline_prompt_write_error
t_pipeline_prompt_flush_error
t_pipeline_confirm_noninteractive
"
run_suite "pipeline tests" "$TESTS"
