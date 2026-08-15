#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

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

t_no_args() {
	td=$1; rc=0; "$PROG" > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: no args should exit non-zero" > "$td/result"
}

t_missing_replace() {
	td=$1; rc=0; "$PROG" find > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: missing REPLACE should exit non-zero" > "$td/result"
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

t_nonexistent_among_valid() {
	td=$1; printf 'good\n' > "$td/good"
	rc=0; "$PROG" good replaced -i "$td/good" "$td/nope" > /dev/null 2>&1 || rc=$?
	[ "$(cat "$td/good")" = 'replaced' ] && [ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: good=[$(cat "$td/good")] rc=$rc" > "$td/result"
}

t_invalid_regex() {
	td=$1; rc=0; msg=$("$PROG" '[' 'X' -E 2>&1 >/dev/null) || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: invalid regex should exit non-zero (got rc=$rc)" > "$td/result"
}

t_long_backup_suffix() {
	td=$1; printf 'content\n' > "$td/f"
	suffix=$(awk 'BEGIN{for(i=0;i<5000;i++) printf "x"}')
	rc=0; msg=$("$PROG" content replaced -i".$suffix" "$td/f" 2>&1 >/dev/null) || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: long backup suffix should error (rc=$rc)" > "$td/result"
}

t_long_backup_suffix_collision() {
	td=$1; printf 'aaa\n' > "$td/f"; printf 'bbb\n' > "$td/f.bak"
	rc=0; "$PROG" aaa replaced -i.bak "$td/f" > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: backup collision should error (rc=$rc)" > "$td/result"
}

t_empty_stdin_inplace_msg() {
	td=$1
	msg=$(printf '' | "$PROG" foo bar -i 2>&1 >/dev/null)
	[ "$(echo "$msg" | grep -c 'backup')" -ge 1 ] && echo PASS > "$td/result" || echo "FAIL: expected error about backup, got [$msg]" > "$td/result"
}

t_readonly_file_direct() {
	td=$1; printf 'alpha\n' > "$td/f"; orig=$(cat "$td/f")
	chmod 000 "$td/f"
	rc=0; msg=$("$PROG" alpha ALPHA -i "$td/f" 2>&1) || rc=$?
	chmod 644 "$td/f"
	now=$(cat "$td/f")
	[ "$rc" -ne 0 ] && [ "$now" = "$orig" ] && printf '%s\n' "$msg" | grep -Fq "$td/f" && echo PASS > "$td/result" || echo "FAIL: rc=$rc now=[$now] msg=[$msg]" > "$td/result"
}

t_readonly_file_recursive() {
	td=$1; mkdir -p "$td/d"; printf 'aa\n' > "$td/d/readable"; printf 'bb\n' > "$td/d/unreadable"; chmod 000 "$td/d/unreadable"
	rc=0; "$PROG" a A -i -r "$td/d" > /dev/null 2>&1 || rc=$?
	chmod 644 "$td/d/unreadable"
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: recursive traversal over unreadable file should error (rc=$rc)" > "$td/result"
}

t_readonly_dir_plain_i() {
	td=$1; mkdir -p "$td/rd"; printf 'qq\n' > "$td/rd/f"
	chmod 555 "$td/rd"
	rc=0; msg=$("$PROG" q Q -i "$td/rd/f" 2>&1) || rc=$?
	chmod 755 "$td/rd"
	now=$(cat "$td/rd/f")
	[ "$rc" -ne 0 ] && [ "$now" = 'qq' ] && printf '%s\n' "$msg" | grep -q 'temporarily write' && echo PASS > "$td/result" || echo "FAIL: rc=$rc now=[$now] msg=[$msg]" > "$td/result"
}

t_readonly_dir_backup() {
	td=$1; mkdir -p "$td/rd"; printf 'qq\n' > "$td/rd/f"
	chmod 555 "$td/rd"
	rc=0; msg=$("$PROG" q Q -i.bak "$td/rd/f" 2>&1) || rc=$?
	chmod 755 "$td/rd"
	now=$(cat "$td/rd/f")
	[ "$rc" -ne 0 ] && [ "$now" = 'qq' ] && printf '%s\n' "$msg" | grep -q 'error processing' && echo PASS > "$td/result" || echo "FAIL: rc=$rc now=[$now] msg=[$msg]" > "$td/result"
}

t_temp_write_failure_enospc() {
	td=$1
	"$PROG_DIR/tests/err_helper" enospc "$td/f" 2000 512 "$td/errlog" -- "$PROG" "x" "y" "-i" "$td/f"
	rc=$?
	[ "$rc" -ne 0 ] && grep -q 'temp file' "$td/errlog" && echo PASS > "$td/result" || echo "FAIL: rc=$rc errlog=[$(cat "$td/errlog" 2>/dev/null)]" > "$td/result"
}

t_closed_stdout_pipe() {
	td=$1
	"$PROG_DIR/tests/err_helper" closed_pipe "$td/in" 100000 -- "$PROG" "x" "y" 2>/dev/null
	rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: closed stdout pipe should error (rc=$rc)" > "$td/result"
}

t_long_relative_path_mkstemp() {
	td=$1; mkdir -p "$td/a"; printf 'zzz\n' > "$td/f"
	P="$td/a/../"
	while [ ${#P} -lt 4088 ]; do P="$P""a/../"; done
	P="$P""f"
	rc=0; msg=$("$PROG" zzz ZZZ -i "$P" 2>&1) || rc=$?
	[ "$rc" -ne 0 ] && printf '%s\n' "$msg" | grep -q 'too large' && echo PASS > "$td/result" || echo "FAIL: rc=$rc pathlen=${#P} msg=[$(printf '%s' "$msg" | head -c 120)]" > "$td/result"
}

t_closed_stderr() {
	td=$1; printf 'foo\n' > "$td/f"
	rc=0; "$PROG" foo bar -i "$td/f" 2>&- || rc=$?
	now=$(cat "$td/f")
	[ "$rc" -ne 0 ] && [ "$now" = 'bar' ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc now=[$now]" > "$td/result"
}

TESTS="
t_stdin_inplace_err
t_stdin_recursive_err
t_nonexistent_file
t_invalid_flag
t_no_find
t_no_args
t_missing_replace
t_include_without_arg
t_exclude_without_arg
t_inplace_backup_collision
t_nonexistent_among_valid
t_invalid_regex
t_long_backup_suffix
t_long_backup_suffix_collision
t_empty_stdin_inplace_msg
t_readonly_file_direct
t_readonly_file_recursive
t_readonly_dir_plain_i
t_readonly_dir_backup
t_temp_write_failure_enospc
t_closed_stdout_pipe
t_long_relative_path_mkstemp
t_closed_stderr
"
run_suite "error path tests" "$TESTS"
