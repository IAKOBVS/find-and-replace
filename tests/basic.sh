#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

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

t_inplace_global() {
	td=$1; printf 'foo foo foo\n' > "$td/f"
	"$PROG" foo bar -i -g "$td/f" 2>/dev/null
	content=$(cat "$td/f")
	[ "$content" = 'bar bar bar' ] && echo PASS > "$td/result" || echo "FAIL: expected [bar bar bar] got [$content]" > "$td/result"
}

t_inplace_backup_global() {
	td=$1; printf 'one one one\n' > "$td/f"
	"$PROG" one two -i.bak -g "$td/f" 2>/dev/null
	c=$(cat "$td/f"); b=$(cat "$td/f.bak" 2>/dev/null)
	[ "$c" = 'two two two' ] && [ "$b" = 'one one one' ] && echo PASS > "$td/result" || echo "FAIL: content [$c] backup [$b]" > "$td/result"
}

t_G_inplace() {
	td=$1; printf 'la la la\n' > "$td/f"
	"$PROG" la lu -i -G "$td/f" 2>/dev/null
	content=$(cat "$td/f")
	[ "$content" = 'lu la la' ] && echo PASS > "$td/result" || echo "FAIL: expected [lu la la] got [$content]" > "$td/result"
}

t_G_inplace_backup() {
	td=$1; printf 'la la la\n' > "$td/f"
	"$PROG" la lu -i.bak -G "$td/f" 2>/dev/null
	c=$(cat "$td/f"); b=$(cat "$td/f.bak" 2>/dev/null)
	[ "$c" = 'lu la la' ] && [ "$b" = 'la la la' ] && echo PASS > "$td/result" || echo "FAIL: content [$c] backup [$b]" > "$td/result"
}

t_no_match() {
	td=$1; out=$(printf 'abc\n' | "$PROG" xyz 'X' 2>/dev/null)
	[ "$out" = 'abc' ] && echo PASS > "$td/result" || echo "FAIL: expected [abc] got [$out]" > "$td/result"
}

t_empty_replace() {
	td=$1; out=$(printf 'hello\n' | "$PROG" lo '' 2>/dev/null)
	[ "$out" = 'hel' ] && echo PASS > "$td/result" || echo "FAIL: expected [hel] got [$out]" > "$td/result"
}

t_zerosized_replacement() {
	td=$1; out=$(printf 'a\n' | "$PROG" a '' 2>/dev/null)
	[ "$out" = '' ] && echo PASS > "$td/result" || echo "FAIL: expected empty got [$out]" > "$td/result"
}

t_empty_input() {
	td=$1; out=$(printf '' | "$PROG" foo bar 2>/dev/null)
	[ "$out" = '' ] && echo PASS > "$td/result" || echo "FAIL: expected [] got [$out]" > "$td/result"
}

t_find_equals_replace() {
	td=$1; out=$(printf 'abc\n' | "$PROG" abc abc 2>/dev/null)
	[ "$out" = 'abc' ] && echo PASS > "$td/result" || echo "FAIL: expected [abc] got [$out]" > "$td/result"
}

t_replace_longer() {
	td=$1; out=$(printf 'ab\n' | "$PROG" ab 'much longer' 2>/dev/null)
	[ "$out" = 'much longer' ] && echo PASS > "$td/result" || echo "FAIL: expected [much longer] got [$out]" > "$td/result"
}

t_inplace_no_change() {
	td=$1; printf 'no match here\n' > "$td/f"; "$PROG" xyzzy REPLACED -i "$td/f" 2>/dev/null
	content=$(cat "$td/f")
	[ "$content" = 'no match here' ] && echo PASS > "$td/result" || echo "FAIL: expected unchanged file got [$content]" > "$td/result"
}

t_combined_i_r() {
	td=$1; printf 'hello\n' > "$td/f"; "$PROG" hello hi -ir "$td/f" 2>/dev/null
	bak=$(cat "$td/fr" 2>/dev/null); orig=$(cat "$td/f" 2>/dev/null)
	[ "$orig" = 'hi' ] && [ "$bak" = 'hello' ] && echo PASS > "$td/result" || echo "FAIL: orig [$orig] bak [$bak]" > "$td/result"
}

TESTS="
t_fixed_stdin
t_global
t_explicit_G
t_inplace
t_inplace_backup
t_inplace_global
t_inplace_backup_global
t_G_inplace
t_G_inplace_backup
t_no_match
t_empty_replace
t_zerosized_replacement
t_empty_input
t_find_equals_replace
t_replace_longer
t_inplace_no_change
t_combined_i_r
"
run_suite "basic tests" "$TESTS"
