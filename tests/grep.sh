#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

RED=$(printf '\033[31m')
GREEN=$(printf '\033[32m')
RESET=$(printf '\033[0m')

t_grep_single_file() {
	td=$1
	printf 'line 1 foo\nline 2 bar\nline 3 foo\n' > "$td/f1"
	out=$("$PROG" foo '' --grep "$td/f1" 2>/dev/null)
	exp="$(printf '%s1%s:line 1 foo\n%s3%s:line 3 foo' "$GREEN" "$RESET" "$GREEN" "$RESET")"
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: expected [$(printf '%s' "$exp" | tr '\033' 'E')] got [$(printf '%s' "$out" | tr '\033' 'E')]" > "$td/result"
}

t_grep_multi_files() {
	td=$1
	printf 'hello world\n' > "$td/f1"
	printf 'bye world\nhello again\n' > "$td/f2"
	out=$("$PROG" hello '' --grep "$td/f1" "$td/f2" 2>/dev/null)
	exp="$(printf '%s%s%s:%s1%s:hello world\n%s%s%s:%s2%s:hello again' "$RED" "$td/f1" "$RESET" "$GREEN" "$RESET" "$RED" "$td/f2" "$RESET" "$GREEN" "$RESET")"
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: expected [$(printf '%s' "$exp" | tr '\033' 'E')] got [$(printf '%s' "$out" | tr '\033' 'E')]" > "$td/result"
}

t_grep_stdin() {
	td=$1
	out=$(printf 'aaa\nbbb\nccc\nbbb2\n' | "$PROG" bbb --grep 2>/dev/null)
	exp="$(printf '%s2%s:bbb\n%s4%s:bbb2' "$GREEN" "$RESET" "$GREEN" "$RESET")"
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: expected [$(printf '%s' "$exp" | tr '\033' 'E')] got [$(printf '%s' "$out" | tr '\033' 'E')]" > "$td/result"
}

t_grep_recursive() {
	td=$1
	mkdir -p "$td/d/sub"
	printf 'target here\n' > "$td/d/f1"
	printf 'nothing\ntarget also here\n' > "$td/d/sub/f2"
	out=$("$PROG" target --grep -r "$td/d" 2>/dev/null | sort)
	exp1="$(printf '%s%s/d/f1%s:%s1%s:target here' "$RED" "$td" "$RESET" "$GREEN" "$RESET")"
	exp2="$(printf '%s%s/d/sub/f2%s:%s2%s:target also here' "$RED" "$td" "$RESET" "$GREEN" "$RESET")"
	exp="$(printf '%s\n%s' "$exp1" "$exp2" | sort)"
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: expected [$(printf '%s' "$exp" | tr '\033' 'E')] got [$(printf '%s' "$out" | tr '\033' 'E')]" > "$td/result"
}

t_grep_flags() {
	td=$1
	printf 'Hello World\nhello world\n' > "$td/f"
	out=$("$PROG" 'HE[L]+O' --grep -I -E "$td/f" 2>/dev/null)
	exp="$(printf '%s1%s:Hello World\n%s2%s:hello world' "$GREEN" "$RESET" "$GREEN" "$RESET")"
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: expected [$(printf '%s' "$exp" | tr '\033' 'E')] got [$(printf '%s' "$out" | tr '\033' 'E')]" > "$td/result"
}

t_grep_no_replace_arg() {
	td=$1
	printf 'foo bar\n' > "$td/f1"
	printf 'bar baz\nfoo qux\n' > "$td/f2"
	out=$("$PROG" foo --grep "$td/f1" "$td/f2" 2>/dev/null)
	exp="$(printf '%s%s%s:%s1%s:foo bar\n%s%s%s:%s2%s:foo qux' "$RED" "$td/f1" "$RESET" "$GREEN" "$RESET" "$RED" "$td/f2" "$RESET" "$GREEN" "$RESET")"
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: expected [$(printf '%s' "$exp" | tr '\033' 'E')] got [$(printf '%s' "$out" | tr '\033' 'E')]" > "$td/result"
}

t_grep_fixed_string() {
	td=$1
	printf 'a.b\na*b\n' > "$td/f"
	out=$("$PROG" 'a.b' --grep -F "$td/f" 2>/dev/null)
	exp="$(printf '%s1%s:a.b' "$GREEN" "$RESET")"
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: expected [$(printf '%s' "$exp" | tr '\033' 'E')] got [$(printf '%s' "$out" | tr '\033' 'E')]" > "$td/result"
}

TESTS="
t_grep_single_file
t_grep_multi_files
t_grep_stdin
t_grep_recursive
t_grep_flags
t_grep_no_replace_arg
t_grep_fixed_string
"
run_suite "grep tests" "$TESTS"
