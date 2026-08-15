#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

t_confirm_yes() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" hello bye -c -i "$td/f" 2>/dev/null)
	[ "$(cat "$td/f")" = 'bye world' ] && echo PASS > "$td/result" || echo "FAIL: expected [bye world] got [$(cat "$td/f")]" > "$td/result"
}

t_confirm_abort() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=0; printf 'n\n' | "$PROG" hello bye -c -i "$td/f" >/dev/null 2>"$td/err" || rc=$?
	[ "$rc" -ne 0 ] && grep -q 'Aborted' "$td/err" && [ "$(cat "$td/f")" = 'hello world' ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc file=[$(cat "$td/f")] err=[$(cat "$td/err")]" > "$td/result"
}

t_confirm_no_inplace_err() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=0; printf 'y\n' | "$PROG" hello bye -c "$td/f" >/dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: -c without -i should error" > "$td/result"
}

t_confirm_stdin_err() {
	td=$1; rc=0; printf 'hello\n' | "$PROG" hello bye -c -i >/dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: -c with stdin should error" > "$td/result"
}

t_confirm_no_match() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" nomatch bye -c -i "$td/f" 2>/dev/null)
	[ -z "$out" ] && [ "$(cat "$td/f")" = 'hello world' ] && echo PASS > "$td/result" || echo "FAIL: out=[$out] file=[$(cat "$td/f")]" > "$td/result"
}

t_confirm_multiline_regex() {
	td=$1; printf 'hello\nworld\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" 'hello\nworld' hi -c -i -R "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'hi' ] && printf '%s' "$clean_out" | grep -q -- '-hello' && printf '%s' "$clean_out" | grep -q -- '+hi' && ! printf '%s' "$clean_out" | grep -q '^@@' && ! printf '%s' "$clean_out" | grep -q '^---' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$out]" > "$td/result"
}

t_confirm_multi_same_line() {
	td=$1; printf 'la la\nla la\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" la lu -c -i -g "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'lu lu
lu lu' ] && [ "$(printf '%s\n' "$clean_out" | grep -c -- '-la la')" -eq 2 ] && [ "$(printf '%s\n' "$clean_out" | grep -c -- '+lu lu')" -eq 2 ] && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$out]" > "$td/result"
}

t_confirm_recursive() {
	td=$1; mkdir -p "$td/d/sub"; printf 'alpha\n' > "$td/d/f1"; printf 'beta\n' > "$td/d/sub/f2"
	out=$(printf 'y\n' | "$PROG" alpha ALPHA -c -i -r "$td/d" 2>/dev/null)
	[ "$(cat "$td/d/f1")" = 'ALPHA' ] && [ "$(cat "$td/d/sub/f2")" = 'beta' ] && echo PASS > "$td/result" || echo "FAIL: f1=[$(cat "$td/d/f1")] f2=[$(cat "$td/d/sub/f2")]" > "$td/result"
}

t_confirm_backup() {
	td=$1; printf 'hello\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" hello bye -c -i.bak "$td/f" 2>/dev/null)
	[ "$(cat "$td/f")" = 'bye' ] && [ "$(cat "$td/f.bak")" = 'hello' ] && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] bak=[$(cat "$td/f.bak" 2>/dev/null)]" > "$td/result"
}

t_confirm_stderr_reports_changed() {
	td=$1; printf 'hello world\n' > "$td/f"
	printf 'y\n' | "$PROG" hello bye -c -i "$td/f" 2>"$td/err" >/dev/null
	[ "$(cat "$td/err")" = "$td/f" ] && echo PASS > "$td/result" || echo "FAIL: stderr=[$(cat "$td/err")]" > "$td/result"
}

t_confirm_stderr_no_report_on_abort() {
	td=$1; printf 'hello world\n' > "$td/f"
	printf 'n\n' | "$PROG" hello bye -c -i "$td/f" 2>"$td/err" >/dev/null
	[ "$(cat "$td/err")" = 'Aborted.' ] && echo PASS > "$td/result" || echo "FAIL: stderr=[$(cat "$td/err")]" > "$td/result"
}

t_confirm_regex_preview_dot_star_g() {
	td=$1; printf 'hello\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" ".*" "world" -gc -i -R "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	expected_file=$(printf 'world\n')
	[ "$(cat "$td/f")" = "$expected_file" ] && printf '%s' "$clean_out" | grep -q -- '-hello' && printf '%s' "$clean_out" | grep -q -- '+world' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_regex_preview_skip_newline() {
	td=$1; printf ' b\n b\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" ".* b" "b" -gc -i -RE "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'b
b' ] && printf '%s' "$clean_out" | grep -q -- '- b' && printf '%s' "$clean_out" | grep -q -- '+b' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_regex_preview_backref() {
	td=$1; printf 'hello\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" "(h)ello" '\\1world' -gc -i -E "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'hworld' ] && printf '%s' "$clean_out" | grep -q -- '-hello' && printf '%s' "$clean_out" | grep -q -- '+hworld' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_preview_line_numbers_shift() {
	td=$1; printf 'a\nhello\nc\nhello\nd\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" hello 'one\ntwo' -c -i -g "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	good=1
	for want in ':2:-hello' ':2:+one' ':3:+two' ':4:-hello' ':5:+one' ':6:+two'; do
		printf '%s\n' "$clean_out" | grep -q -- "$want" || good=0
	done
	exp='a
one
two
c
one
two
d'
	[ "$good" -eq 1 ] && [ "$(cat "$td/f")" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_preview_no_trailing_newline() {
	td=$1; printf 'no newline' > "$td/f"
	out=$(printf 'y\n' | "$PROG" no yes -c -i "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'yes newline' ] && printf '%s' "$clean_out" | grep -q -- ':1:-no newline' && printf '%s' "$clean_out" | grep -q -- ':1:+yes newline' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_preview_delete_line() {
	td=$1; printf 'DELETE\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" DELETE '' -c -i "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(wc -c < "$td/f")" -eq 1 ] && printf '%s' "$clean_out" | grep -q -- ':1:-DELETE' && printf '%s' "$clean_out" | grep -q -- ':1:+$' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_preview_empty_line_insert() {
	td=$1; printf 'a\n\nb\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" '^$' X -gc -i -R "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	exp='a
X
b'
	[ "$(cat "$td/f")" = "$exp" ] && printf '%s' "$clean_out" | grep -q -- ':2:-$' && printf '%s' "$clean_out" | grep -q -- ':2:+X' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_preview_many_blocks() {
	td=$1
	i=1; : > "$td/f"
	while [ $i -le 5000 ]; do
		if [ $((i % 100)) -eq 0 ]; then printf 'X\n' >> "$td/f"; else printf 'line\n' >> "$td/f"; fi
		i=$((i + 1))
	done
	out=$(printf 'y\n' | "$PROG" X Y -c -i -g "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	n=$(printf '%s\n' "$clean_out" | grep -c -- ':-X$')
	yg=$(tr -cd 'Y' < "$td/f" | wc -c)
	xg=$(tr -cd 'X' < "$td/f" | wc -c)
	[ "$n" -eq 50 ] && [ "$yg" -eq 50 ] && [ "$xg" -eq 0 ] && printf '%s\n' "$clean_out" | grep -q -- ':100:-X' && printf '%s\n' "$clean_out" | grep -q -- ':5000:-X' && printf '%s\n' "$clean_out" | grep -q -- ':5000:+Y' && echo PASS > "$td/result" || echo "FAIL: n=$n yg=$yg xg=$xg out=[$(printf '%s\n' "$clean_out" | head -3)]" > "$td/result"
}

t_confirm_interactive_live_preview() {
	td=$1; printf 'hello world\n' > "$td/f"
	"$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 7f7f7f7f7f -s "world" -k 0d -w 300 -s "y\n" -- "$PROG" hello replacement -c -i "$td/f" 2>/dev/null
	[ "$(cat "$td/f")" = 'hello replacement' ] && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")]" > "$td/result"
}

t_confirm_interactive_multi_field() {
	td=$1; printf 'hello world\n' > "$td/f1"; printf 'hello again\n' > "$td/f2"
	"$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 0915 -s "newreplace" -k 0915 -s "gR" -k 09 -s "f2" -k 0d -w 300 -s "y\n" -- "$PROG" hello replacement -c -i "$td/f1" "$td/f2" 2>/dev/null
	[ "$(cat "$td/f1")" = 'hello world' ] && [ "$(cat "$td/f2")" = 'newreplace again' ] && echo PASS > "$td/result" || echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")]" > "$td/result"
}

t_confirm_interactive_layout() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 0d -w 300 -s "n\n" -p -- "$PROG" hello replacement -c -i "$td/f" 2>/dev/null)
	if echo "$out" | grep -q -- '-- \[INSERT\] --' && echo "$out" | grep -q 'Find:    hello' && echo "$out" | grep -q 'Replace: replacement'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: layout check failed. out=[$out]" > "$td/result"
	fi
}

t_confirm_interactive_error_preview() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 090915 -s "gR" -k 090909090915 -s "[" -k 09 -s "abc" -k 03 -p -- "$PROG" hello replacement -c -i "$td/f" 2>/dev/null)
	if echo "$out" | grep -q 'Regex error:' && echo "$out" | grep -q 'Replace: replacementabc'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: error preview check failed. out=[$out]" > "$td/result"
	fi
}

t_confirm_interactive_backref_mismatch() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 090915 -s "gR" -w 1000 -k 03 -p -- "$PROG" hello "\\\\\\\\1\\\\\\\\2" -c -i "$td/f" 2>/dev/null)
	if printf '%s\n' "$out" | grep -q 'Replace backreference \\2 exceeds find capture groups (0)'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: backref mismatch not found. out=[$out]" > "$td/result"
	fi
}

t_confirm_non_interactive_backref_mismatch() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=0
	"$PROG" '(hello)' '\\1\\2' -R -i "$td/f" >/dev/null 2>"$td/err" || rc=$?
	if [ "$rc" -ne 0 ] && grep -q 'Replace backreference \\2 exceeds find capture groups (0)' "$td/err"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc err=[$(cat "$td/err" 2>/dev/null)]" > "$td/result"
	fi
}

t_confirm_interactive_stats() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 0d -w 300 -s "n\n" -p -- "$PROG" hello replacement -c -i "$td/f" 2>/dev/null)
	if echo "$out" | grep -q '1 matches, 1 files'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: stats not found. out=[$out]" > "$td/result"
	fi
}

t_confirm_interactive_height_capping() {
	td=$1; printf 'line 1\nline 2\nline 3\nline 4\nline 5\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -r 12 -c 80 -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 0d -w 300 -s "n\n" -p -- "$PROG" line replacement -c -i -g "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	lines_count=$(printf '%s\n' "$out" | grep '_interactive_height_capping/f' | grep -c '\[K')
	if printf '%s\n' "$clean_out" | grep -q 'some previews omitted' && [ "$lines_count" -le 3 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: height capping failed. lines=$lines_count out=[$clean_out]" > "$td/result"
	fi
}

t_confirm_interactive_tab_expansion() {
	td=$1; printf '\thello world\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -r 24 -c 80 -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 0d -w 300 -s "n\n" -p -- "$PROG" hello replacement -c -i "$td/f" 2>/dev/null)
	tui_out=$(printf '%s\n' "$out" | grep '\[K')
	clean_tui=$(printf '%s\n' "$tui_out" | sed 's/\x1b\[[0-9;]*m//g; s/\x1b\[K//g; s/\[K//g')
	if printf '%s\n' "$clean_tui" | grep -q ':-   hello world' && ! printf '%s\n' "$clean_tui" | grep -q ':\t'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: tab expansion failed. tui=[$clean_tui]" > "$td/result"
	fi
}

t_confirm_interactive_width_clipping() {
	td=$1
	awk 'BEGIN{for(i=0;i<150;i++) printf "a"; print ""}' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -r 24 -c 80 -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 0d -w 300 -s "n\n" -p -- "$PROG" a b -c -i "$td/f" 2>/dev/null)
	tui_out=$(printf '%s\n' "$out" | grep '_interactive_width_clipping/f:1:-' | grep '\[K' | head -1)
	clean_line=$(printf '%s\n' "$tui_out" | sed -E 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\r//g')
	if [ -n "$clean_line" ] && [ "${#clean_line}" -le 79 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: width clipping failed. line_len=${#clean_line} line=[$clean_line]" > "$td/result"
	fi
}

t_confirm_vim_motions() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 1b -w 200 -k 30 -w 100 -k 78 -w 100 -k 24 -w 100 -k 69 -w 100 -s "X" -w 100 -k 1b -w 200 -k 6a -w 100 -k 30 -w 100 -k 78 -w 100 -k 0d -w 300 -s "y\n" -p -- "$PROG" hello replacement -c -i "$td/f" 2>/dev/null)
	if [ "$(cat "$td/f")" = 'hello world' ] && echo "$out" | grep -q -- '-- \[NORMAL\] --'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim motions check failed. f=[$(cat "$td/f")] out=[$out]" > "$td/result"
	fi
}

t_confirm_vim_word_motions() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 1b -w 200 -k 30 -w 100 -k 77 -w 100 -k 78 -w 100 -k 62 -w 100 -k 78 -w 100 -k 0d -w 300 -s "y\n" -p -- "$PROG" "foo-bar baz" replacement -c -i "$td/f" 2>/dev/null)
	if echo "$out" | grep -q 'Find:    oobar baz'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim word motions check failed. out=[$out]" > "$td/result"
	fi
}

t_confirm_vim_delete_eol() {
	td=$1; printf 'hell world\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 1b -w 200 -k 78 -w 200 -k 0d -w 300 -s "y\n" -p -- "$PROG" hello replacement -c -i "$td/f" 2>/dev/null)
	if echo "$out" | grep -q 'Find:    hell'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim delete eol check failed. out=[$out]" > "$td/result"
	fi
}

t_confirm_vim_delete_dd() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 1b -w 200 -k 6464 -w 200 -s "ihello" -w 200 -k 0d -w 300 -s "y\n" -p -- "$PROG" hello replacement -c -i "$td/f" 2>/dev/null)
	if echo "$out" | grep -q 'Find:    hello' && [ "$(cat "$td/f")" = 'replacement world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim dd check failed. out=[$out]" > "$td/result"
	fi
}

t_confirm_vim_change_cw() {
	td=$1; printf 'qux-bar world\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 1b -w 200 -k 30 -w 100 -s "cwqux" -w 200 -k 0d -w 300 -s "y\n" -p -- "$PROG" foo-bar replacement -c -i "$td/f" 2>/dev/null)
	if echo "$out" | grep -q 'Find:    qux-bar' && [ "$(cat "$td/f")" = 'replacement world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim cw check failed. out=[$out]" > "$td/result"
	fi
}

t_confirm_interactive_include_exclude() {
	td=$1; mkdir -p "$td/d"
	printf 'hello\n' > "$td/d/a.txt"; printf 'hello\n' > "$td/d/b.txt"; printf 'hello\n' > "$td/d/c.c"
	"$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 0909090915 -s "\\.txt$" -k 0915 -s "^b" -w 300 -k 0d -w 300 -s "y\n" -- "$PROG" hello HI -c -i -r "$td/d" 2>/dev/null
	ta=$(cat "$td/d/a.txt"); tb=$(cat "$td/d/b.txt"); tc=$(cat "$td/d/c.c")
	[ "$ta" = 'HI' ] && [ "$tb" = 'hello' ] && [ "$tc" = 'hello' ] && echo PASS > "$td/result" || echo "FAIL: a [$ta] b [$tb] c [$tc]" > "$td/result"
}

t_confirm_interactive_backup() {
	td=$1; printf 'hello\n' > "$td/f"
	"$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 09090909090915 -s "bak" -w 300 -k 0d -w 300 -s "y\n" -- "$PROG" hello HI -c -i "$td/f" 2>/dev/null
	[ "$(cat "$td/f")" = 'HI' ] && [ "$(cat "$td/fbak")" = 'hello' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")] fbak=[$(cat "$td/fbak" 2>/dev/null)]" > "$td/result"
}

t_confirm_interactive_l_flag() {
	td=$1; printf 'hello\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 090915 -s "l" -w 300 -k 0d -w 300 -s "y\n" -p -- "$PROG" hello HI -c -i "$td/f" 2>/dev/null)
	[ "$(cat "$td/f")" = 'HI' ] && printf '%s\n' "$out" | grep -q "$td/f" && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")] path-not-printed" > "$td/result"
}

t_confirm_interactive_clear_filters() {
	td=$1; mkdir -p "$td/d"
	printf 'hello\n' > "$td/d/a.txt"; printf 'hello\n' > "$td/d/b.txt"
	"$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 09090909 -s "\\.txt$" -k 1509 -s "^b" -k 15 -w 300 -k 0d -w 300 -s "y\n" -- "$PROG" hello HI -c -i -r "$td/d" 2>/dev/null
	ta=$(cat "$td/d/a.txt"); tb=$(cat "$td/d/b.txt")
	[ "$ta" = 'HI' ] && [ "$tb" = 'HI' ] && echo PASS > "$td/result" || echo "FAIL: a [$ta] b [$tb]" > "$td/result"
}

t_confirm_interactive_invalid_exclude() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 0909090909 -s "[" -k 03 -p -- "$PROG" hello HI -c -i "$td/f" 2>/dev/null)
	if echo "$out" | grep -q 'Invalid Exclude regex'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: invalid exclude regex not reported. out=[$out]" > "$td/result"
	fi
}

t_confirm_interactive_flags_ei() {
	td=$1; printf 'HeLLo world\n' > "$td/f"
	"$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 090915 -s "EIz" -w 300 -k 0d -w 300 -s "y\n" -- "$PROG" hello HI -c -i "$td/f" 2>/dev/null
	[ "$(cat "$td/f")" = 'HI world' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")]" > "$td/result"
}

t_vim_normal_mode_word_motions() {
	td=$1; printf 'foo bar az\n' > "$td/f"
	rc=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 1b -w 200 -k 30,77,77,78,62,77,77,0d -w 300 -s "y\n" -o "$td/out" -x -- "$PROG" "foo bar baz" X -c -i "$td/f" 2>/dev/null)
	if [ "$rc" = 0 ] && [ "$(cat "$td/f")" = 'X' ] && grep -q 'Find:    foo bar az' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc f=[$(cat "$td/f")] out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

drive() {
	f=$1; find=$2; rplc=$3; keys=$4; tail=$5
	"$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k "$keys" -w 200 -k 0d -w 300 -s "$tail" -- "$PROG" "$find" "$rplc" -c -i "$f" 2>/dev/null
}

t_vim_delete_ops() {
	td=$1
	good=1
	# dw: 0 d w -> find "bar baz"
	printf 'foo bar baz\n' > "$td/f1"
	drive "$td/f1" 'foo bar baz' X '1b,30,64,77' 'y\n'
	[ "$(cat "$td/f1")" = 'foo X' ] || good=0
	# db: $ d b -> find "foo bar z" (no match, cursor clamps to end-1)
	printf 'foo bar baz\n' > "$td/f2"
	drive "$td/f2" 'foo bar baz' X '1b,24,64,62' 'y\n'
	[ "$(cat "$td/f2")" = 'foo bar baz' ] || good=0
	# d0: $ d 0 -> find "z"
	printf 'foo bar baz\n' > "$td/f3"
	drive "$td/f3" 'foo bar baz' X '1b,24,64,30' 'y\n'
	[ "$(cat "$td/f3")" = 'foo bar baX' ] || good=0
	# d0: b d 0 -> find "baz"
	printf 'foo bar baz\n' > "$td/f4"
	drive "$td/f4" 'foo bar baz' X '1b,62,64,30' 'y\n'
	[ "$(cat "$td/f4")" = 'foo bar X' ] || good=0
	# d$: 0 d $ -> find empty, no matches, file untouched
	printf 'foo bar baz\n' > "$td/f5"
	drive "$td/f5" 'foo bar baz' X '1b,30,64,24' 'y\n'
	[ "$(cat "$td/f5")" = 'foo bar baz' ] || good=0
	# dd: 0 d d -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f6"
	drive "$td/f6" 'foo bar baz' X '1b,30,64,64' 'y\n'
	[ "$(cat "$td/f6")" = 'foo bar baz' ] || good=0
	# x: 0 x -> delete first char -> find "oo bar baz"
	printf 'foo bar baz\n' > "$td/f7"
	drive "$td/f7" 'foo bar baz' X '1b,30,78' 'y\n'
	[ "$(cat "$td/f7")" = 'fX' ] || good=0
	# X: $ X -> delete char before end cursor -> find "foo bar bz" (no match)
	printf 'foo bar baz\n' > "$td/f8"
	drive "$td/f8" 'foo bar baz' X '1b,24,58' 'y\n'
	[ "$(cat "$td/f8")" = 'foo bar baz' ] || good=0
	# D: 0 D -> delete to end -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f9"
	drive "$td/f9" 'foo bar baz' X '1b,30,44' 'y\n'
	[ "$(cat "$td/f9")" = 'foo bar baz' ] || good=0
	if [ "$good" -eq 1 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")] f3=[$(cat "$td/f3")] f4=[$(cat "$td/f4")] f5=[$(cat "$td/f5")] f6=[$(cat "$td/f6")] f7=[$(cat "$td/f7")] f8=[$(cat "$td/f8")] f9=[$(cat "$td/f9")]" > "$td/result"
	fi
}

t_vim_change_ops() {
	td=$1
	good=1
	# cw: 0 c w -> find "bar baz", insert mode
	printf 'foo bar baz\n' > "$td/f1"
	drive "$td/f1" 'foo bar baz' X '1b,30,63,77' 'y\n'
	[ "$(cat "$td/f1")" = 'foo X' ] || good=0
	# cb: 0 c b -> no-op (cursor at 0), find unchanged
	printf 'foo bar baz\n' > "$td/f2"
	drive "$td/f2" 'foo bar baz' X '1b,30,63,62' 'y\n'
	[ "$(cat "$td/f2")" = 'X' ] || good=0
	# c0: $ c 0 -> find "z"
	printf 'foo bar baz\n' > "$td/f3"
	drive "$td/f3" 'foo bar baz' X '1b,24,63,30' 'y\n'
	[ "$(cat "$td/f3")" = 'foo bar baX' ] || good=0
	# c$: 0 c $ -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f4"
	drive "$td/f4" 'foo bar baz' X '1b,30,63,24' 'y\n'
	[ "$(cat "$td/f4")" = 'foo bar baz' ] || good=0
	# cc: 0 c c -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f5"
	drive "$td/f5" 'foo bar baz' X '1b,30,63,63' 'y\n'
	[ "$(cat "$td/f5")" = 'foo bar baz' ] || good=0
	# C: 0 w C -> find "foo ", file "Xbar baz"
	printf 'foo bar baz\n' > "$td/f6"
	drive "$td/f6" 'foo bar baz' X '1b,30,77,43' 'y\n'
	[ "$(cat "$td/f6")" = 'Xbar baz' ] || good=0
	# C: 0 C -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f7"
	drive "$td/f7" 'foo bar baz' X '1b,30,43' 'y\n'
	[ "$(cat "$td/f7")" = 'foo bar baz' ] || good=0
	if [ "$good" -eq 1 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")] f3=[$(cat "$td/f3")] f4=[$(cat "$td/f4")] f5=[$(cat "$td/f5")] f6=[$(cat "$td/f6")] f7=[$(cat "$td/f7")]" > "$td/result"
	fi
}

t_vim_insert_motions() {
	td=$1
	good=1
	# I: insert at home -> find "Xhello"
	printf 'Xhello world\n' > "$td/f1"
	drive "$td/f1" hello R '1b,49,58' 'y\n'
	[ "$(cat "$td/f1")" = 'R world' ] || good=0
	# A: insert at end -> find "helloX"
	printf 'helloX world\n' > "$td/f2"
	drive "$td/f2" hello R '1b,41,58' 'y\n'
	[ "$(cat "$td/f2")" = 'R world' ] || good=0
	# 0 l i: insert at cursor 1 -> find "hXello"
	printf 'hXello world\n' > "$td/f3"
	drive "$td/f3" hello R '1b,30,6c,69,58' 'y\n'
	[ "$(cat "$td/f3")" = 'R world' ] || good=0
	# 0 l a: append after cursor -> find "heXllo"
	printf 'heXllo world\n' > "$td/f4"
	drive "$td/f4" hello R '1b,30,6c,61,58' 'y\n'
	[ "$(cat "$td/f4")" = 'R world' ] || good=0
	if [ "$good" -eq 1 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")] f3=[$(cat "$td/f3")] f4=[$(cat "$td/f4")]" > "$td/result"
	fi
}

t_vim_jk_field_nav() {
	td=$1
	good=1
	# j: down to Replace, i inserts at cursor (clamped to end-1), type zz
	printf 'hello world\n' > "$td/f1"
	drive "$td/f1" hello replacement '1b,6a,69,7a,7a' 'y\n'
	[ "$(cat "$td/f1")" = 'replacemenzzt world' ] || good=0
	# k k j: up to Backup (wrap), down to Exclude... then j to Backup, type bak suffix
	printf 'hello world\n' > "$td/f2"
	drive "$td/f2" hello replacement '1b,6b,6b,6a,69,62616b' 'y\n'
	[ "$(cat "$td/f2")" = 'replacement world' ] || good=0
	[ "$(cat "$td/f2bak" 2>/dev/null)" = 'hello world' ] || good=0
	if [ "$good" -eq 1 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")] f2bak=[$(cat "$td/f2bak" 2>/dev/null)]" > "$td/result"
	fi
}

t_terminal_size_zero() {
	td=$1
	i=1; : > "$td/f"
	while [ $i -le 20 ]; do printf 'X\n' >> "$td/f"; i=$((i + 1)); done
	rc=$("$PROG_DIR/tests/pty_driver" -e "LINES=" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 0d -w 300 -s "y\n" -o "$td/out" -x -- "$PROG" X Y -c -i -g "$td/f" 2>/dev/null)
	yg=$(tr -cd 'Y' < "$td/f" | wc -c)
	if [ "$rc" = 0 ] && [ "$yg" -eq 20 ] && grep -q '20 matches, 1 files' "$td/out" && grep -q 'some previews omitted' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc yg=$yg out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

t_terminal_cols_env() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=$("$PROG_DIR/tests/pty_driver" -e "COLUMNS=30" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 0d -w 300 -s "y\n" -o "$td/out" -x -- "$PROG" hello HI -c -i "$td/f" 2>/dev/null)
	if [ "$rc" = 0 ] && [ "$(cat "$td/f")" = 'HI world' ] && grep -q '1 matches, 1 files' "$td/out" && grep -q 'Find:    hello' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc f=[$(cat "$td/f")] out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

t_interactive_signal_term() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -K 15 -x -- "$PROG" hello HI -c -i "$td/f" 2>/dev/null)
	if [ "$rc" = 1 ] && [ "$(cat "$td/f")" = 'hello world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_interactive_file_deleted_rename_fail() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -A "unlink_mkdir:$td/f" -k 0d -w 300 -s "y\n" -p -x -- "$PROG" hello bye -c -i "$td/f" 2>/dev/null)
	has_err=False
	if echo "$out" | grep -q 'rename temp file'; then
		has_err=True
	fi
	last_line=$(echo "$out" | tail -n 1)
	if [ "$last_line" = "1" ] && [ "$has_err" = "True" ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

t_interactive_invalid_flag_char() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=$("$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 090915 -s "x" -k 0d -w 300 -s "n\n" -o "$td/out" -x -- "$PROG" hello HI -c -i "$td/f" 2>/dev/null)
	if [ "$rc" = 1 ] && grep -q 'Flags:   x' "$td/out" && [ "$(cat "$td/f")" = 'hello world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

t_interactive_arrows() {
	td=$1
	good=1
	# up, down, right, left, right (restore cursor), shift-tab, delete, shift-tab,
	# down, down (back to Find), type X -> find "helloX"
	printf 'helloX world\n' > "$td/f1"
	drive "$td/f1" hello replacement '1b5b41,1b5b42,1b5b43,1b5b44,1b5b43,1b5b5a,1b5b337e,1b5b5a,1b5b42,1b5b42,58' 'y\n'
	[ "$(cat "$td/f1")" = 'replacement world' ] || good=0
	# ESC 0 then Delete key in normal mode deletes first char -> find "ello"
	printf 'hello world\n' > "$td/f2"
	drive "$td/f2" hello replacement '1b,30,1b5b337e' 'y\n'
	[ "$(cat "$td/f2")" = 'hreplacement world' ] || good=0
	if [ "$good" -eq 1 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")]" > "$td/result"
	fi
}

t_interactive_ctrl_j_k() {
	td=$1; printf 'hello world\n' > "$td/f"
	drive "$td/f" hello replacement '0a,0a,0b,7a,7a' 'y\n'
	[ "$(cat "$td/f")" = 'replacementzz world' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")]" > "$td/result"
}

t_vim_match_line_end() {
	td=$1; printf 'a\nb\nc\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" 'a\nb' 'X' -c -i -R "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	if [ "$(cat "$td/f")" = 'X
c' ] && printf '%s\n' "$clean_out" | grep -q -- '-a' && printf '%s\n' "$clean_out" | grep -q -- '-b' && printf '%s\n' "$clean_out" | grep -q -- '+X' && ! printf '%s\n' "$clean_out" | grep -q -- '-c'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
	fi
}

t_confirm_regex_scan_empty() {
	td=$1; printf '\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" '^$' X -c -i -R -g "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	if [ "$(cat "$td/f")" = 'X' ] && printf '%s\n' "$clean_out" | grep -q -- ':1:-$' && printf '%s\n' "$clean_out" | grep -q -- ':1:+X'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
	fi
}

t_vim_dd() {
	td=$1; printf 'foo bar baz\n' > "$td/f"
	drive "$td/f" 'foo bar' X '1b,64,64' 'n\n'
	[ "$(cat "$td/f")" = 'foo bar baz' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")]" > "$td/result"
}

t_confirm_abstractions() {
	td=$1; printf 'hello abstractions\n' > "$td/f"
	"$PROG_DIR/tests/pty_driver" -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 0a -s "!!" -k 0b -w 200 -k 0d -w 300 -s "y\n" -- "$PROG" hello world -c -i "$td/f" 2>/dev/null
	[ "$(cat "$td/f")" = 'world!! abstractions' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")]" > "$td/result"
}

t_confirm_interactive_no_scroll() {
	td=$1
	i=1; : > "$td/f"
	while [ $i -le 20 ]; do printf 'line %d hello\n' "$i" >> "$td/f"; i=$((i + 1)); done
	out=$("$PROG_DIR/tests/pty_driver" -r 24 -c 80 -e "LD_LIBRARY_PATH=$PROG_DIR/lib/jstring/build/lib" -w 300 -k 0d -w 300 -s "n\n" -p -- "$PROG" hello world -c -i -g "$td/f" 2>/dev/null)
	ESC=$(printf '\033')
	nl_count=$(printf '%s' "$out" | awk -v esc="$ESC" '
	BEGIN {
		pat = esc "[2J" esc "[H"
	}
	{
		buf = (buf == "" ? $0 : buf "\n" $0)
	}
	END {
		idx = 0
		p = 1
		while ((n = index(substr(buf, p), pat)) > 0) {
			idx = p + n - 1
			p = idx + length(pat)
		}
		if (idx > 0) {
			frame = substr(buf, idx)
		} else {
			frame = buf
		}
		match_pos = 0
		for (i = 1; i <= length(frame); i++) {
			if (substr(frame, i) ~ ("^" esc "\\[[0-9]+;[0-9]+H")) {
				match_pos = i
				break
			}
		}
		if (match_pos > 0) {
			before = substr(frame, 1, match_pos - 1)
			nlines = 0
			for (i = 1; i <= length(before); i++) {
				if (substr(before, i, 1) == "\n") nlines++
			}
			print nlines
		} else {
			print "no_match"
		}
	}')
	if [ "$nl_count" = "23" ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: terminal scrolled during interactive render (newlines=$nl_count)" > "$td/result"
	fi
}

TESTS="
t_confirm_yes
t_confirm_abort
t_confirm_no_inplace_err
t_confirm_stdin_err
t_confirm_no_match
t_confirm_multiline_regex
t_confirm_multi_same_line
t_confirm_recursive
t_confirm_backup
t_confirm_stderr_reports_changed
t_confirm_stderr_no_report_on_abort
t_confirm_regex_preview_dot_star_g
t_confirm_regex_preview_skip_newline
t_confirm_regex_preview_backref
t_confirm_preview_line_numbers_shift
t_confirm_preview_no_trailing_newline
t_confirm_preview_delete_line
t_confirm_preview_empty_line_insert
t_confirm_preview_many_blocks
t_confirm_interactive_live_preview
t_confirm_interactive_multi_field
t_confirm_interactive_layout
t_confirm_interactive_error_preview
t_confirm_interactive_backref_mismatch
t_confirm_non_interactive_backref_mismatch
t_confirm_interactive_stats
t_confirm_interactive_height_capping
t_confirm_interactive_tab_expansion
t_confirm_interactive_width_clipping
t_confirm_vim_motions
t_confirm_vim_word_motions
t_confirm_vim_delete_eol
t_confirm_vim_delete_dd
t_confirm_vim_change_cw
t_confirm_interactive_include_exclude
t_confirm_interactive_backup
t_confirm_interactive_l_flag
t_confirm_interactive_clear_filters
t_confirm_interactive_invalid_exclude
t_confirm_interactive_flags_ei
t_vim_normal_mode_word_motions
t_vim_delete_ops
t_vim_change_ops
t_vim_insert_motions
t_vim_jk_field_nav
t_terminal_size_zero
t_terminal_cols_env
t_interactive_signal_term
t_interactive_file_deleted_rename_fail
t_interactive_invalid_flag_char
t_interactive_arrows
t_interactive_ctrl_j_k
t_vim_match_line_end
t_confirm_regex_scan_empty
t_vim_dd
t_confirm_abstractions
t_confirm_interactive_no_scroll
"

run_suite "confirm tests" "$TESTS"
