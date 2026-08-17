#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

PDRV="$PROG_DIR/tests/pty_drive.py"

# pdrive [--out FILE] [--rc FILE] [--noready] [--phase HEX[@MS] ...] [--tail TEXT] -- [tool args...]
# Runs the tool under a pty, feeding --phase hex bytes (default 100ms sleep
# before each; @MS overrides) and --tail literal text, capturing pty output to
# $td/out and the child outcome (0 / 1 / sig:<N> / timeout) to $td/rc. Waits
# for the TUI's '-- [INSERT] --' render by default (--noready disables).
pdrive() {
	use_ready=1
	for a in "$@"; do
		case "$a" in
			--ready) use_ready=0 ;;
			--noready) use_ready=0 ;;
		esac
	done
	if [ "$use_ready" -eq 1 ]; then
		set -- --ready '-- [INSERT] --' "$@"
	fi
	python3 "$PDRV" --prog "$PROG" --out "$td/out" --rc "$td/rc" "$@" >/dev/null 2>&1
}

t_confirm_yes() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" hello bye -c -i "$td/f" 2>/dev/null)
	[ "$(cat "$td/f")" = 'bye world' ] && echo PASS > "$td/result" || echo "FAIL: expected [bye world] got [$(cat "$td/f")]" > "$td/result"
}

t_confirm_colored_default() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$("$PROG" hello bye -c -i "$td/f" < /dev/null 2>/dev/null)
	red=$(printf '\033[31m'); green=$(printf '\033[32m')
	case "$out" in
		*"$red"*"$green"*) echo PASS > "$td/result" ;;
		*) echo "FAIL: -c output has no red/green color codes (colors should be unconditional)" > "$td/result" ;;
	esac
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
	# Under latest jstring, ".* b" replaced with "b" (with REG_NEWLINE) produces "b\nb\n"
	[ "$(cat "$td/f")" = 'b
b' ] && printf '%s' "$clean_out" | grep -q -- '- b' && printf '%s' "$clean_out" | grep -q -- '+b' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_regex_preview_backref() {
	td=$1; printf 'hello\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" "(h)ello" '\\1world' -gc -i -E "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'hworld' ] && printf '%s\n' "$clean_out" | grep -q -- '-hello' && printf '%s\n' "$clean_out" | grep -q -- '+hworld' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_preview_line_numbers_shift() {
	td=$1; printf 'a\nhello\nc\nhello\nd\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" hello 'one\ntwo' -c -i -g "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
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
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'yes newline' ] && printf '%s\n' "$clean_out" | grep -q -- ':1:-no newline' && printf '%s\n' "$clean_out" | grep -q -- ':1:+yes newline' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_preview_delete_line() {
	td=$1; printf 'DELETE\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" DELETE '' -c -i "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(wc -c < "$td/f")" -eq 1 ] && printf '%s\n' "$clean_out" | grep -q -- ':1:-DELETE' && printf '%s\n' "$clean_out" | grep -q -- ':1:+$' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_preview_empty_line_insert() {
	td=$1; printf 'a\n\nb\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" '^$' X -gc -i -R "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	exp='a
X
b'
	[ "$(cat "$td/f")" = "$exp" ] && printf '%s\n' "$clean_out" | grep -q -- ':2:-$' && printf '%s\n' "$clean_out" | grep -q -- ':2:+X' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_preview_many_blocks() {
	td=$1
	i=1; : > "$td/f"
	while [ $i -le 5000 ]; do
		if [ $((i % 100)) -eq 0 ]; then printf 'X\n' >> "$td/f"; else printf 'line\n' >> "$td/f"; fi
		i=$((i + 1))
	done
	out=$(printf 'y\n' | "$PROG" X Y -c -i -g "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	n=$(printf '%s\n' "$clean_out" | grep -c -- ':-X$')
	yg=$(tr -cd 'Y' < "$td/f" | wc -c)
	xg=$(tr -cd 'X' < "$td/f" | wc -c)
	[ "$n" -eq 50 ] && [ "$yg" -eq 50 ] && [ "$xg" -eq 0 ] && printf '%s\n' "$clean_out" | grep -q -- ':100:-X' && printf '%s\n' "$clean_out" | grep -q -- ':5000:-X' && printf '%s\n' "$clean_out" | grep -q -- ':5000:+Y' && echo PASS > "$td/result" || echo "FAIL: n=$n yg=$yg xg=$xg out=[$(printf '%s\n' "$clean_out" | head -3)]" > "$td/result"
}

t_confirm_interactive_live_preview() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --tail '\x7f\x7f\x7f\x7f\x7fworld\r' --tail 'y\n' -- hello replacement -c -i "$td/f"
	[ "$(cat "$td/f")" = 'hello replacement' ] && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")]" > "$td/result"
}

t_confirm_interactive_multi_field() {
	td=$1; printf 'hello world\n' > "$td/f1"; printf 'hello again\n' > "$td/f2"
	pdrive --tail '\t\x15newreplace\t\x15gR\tf2\r' --tail 'y\n' -- hello replacement -c -i "$td/f1" "$td/f2"
	[ "$(cat "$td/f1")" = 'hello world' ] && [ "$(cat "$td/f2")" = 'newreplace again' ] && echo PASS > "$td/result" || echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")]" > "$td/result"
}

t_confirm_interactive_layout() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --tail '\r' --tail 'n\n' -- hello replacement -c -i "$td/f"
	if grep -q -- '-- \[INSERT\] --' "$td/out" && grep -q 'Find:    hello' "$td/out" && grep -q 'Replace: replacement' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: layout check failed. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_interactive_error_preview() {
	td=$1; printf 'hello world\n' > "$td/f"
	# 1. Tab to Flags (\t\t), clear (\x15), set to gR
	# 2. Tab back to Find (5 tabs), clear (\x15), type invalid regex "["
	# 3. Tab to Replace (\t), type "abc"
	# 4. Abort with Ctrl-C (\x03) so we can inspect output
	pdrive --tail '\t\t\x15gR\t\t\t\t\t\x15[\tabc\x03' -- hello replacement -c -i "$td/f"
	# Check that the "Regex error:" string appears in the final frame where Replace contains "replacementabc"
	if grep -q 'Regex error:' "$td/out" && grep -q 'Replace: replacementabc' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: error preview check failed. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_interactive_backref_mismatch() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --tail '\t\t\x15gR' --tail '\x03' -- hello '\\\\1\\\\2' -c -i "$td/f"
	if grep -q 'Replace backreference \\2 exceeds find capture groups (0)' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: backref mismatch not found. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_interactive_escape_find() {
	td=$1; printf 'a\tb\n' > "$td/f"
	# Ctrl-U clears the FIND field, then type literal \t (backslash-t). The
	# interactive field must unescape it like the CLI arg would.
	pdrive --tail '\x15' --tail '\\t' --tail '\r' --tail 'y\n' -- hello world -c -i "$td/f"
	if [ "$(cat "$td/f")" = 'aworldb' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: typed \\t find not unescaped. got=[$(cat -v "$td/f")]" > "$td/result"
	fi
}

t_confirm_interactive_escape_replace() {
	td=$1; printf 'hello\n' > "$td/f"
	printf '\n\n' > "$td/exp"
	# Tab to REPLACE, clear it, type literal \n, apply.
	pdrive --tail '\x09' --tail '\x15' --tail '\\n' --tail '\r' --tail 'y\n' -- hello X -c -i "$td/f"
	if cmp -s "$td/f" "$td/exp"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: typed \\n replace not unescaped. got=[$(cat -v "$td/f")]" > "$td/result"
	fi
}

t_confirm_interactive_escape_live_preview() {
	td=$1; printf 'a\tb\n' > "$td/f"
	tab=$(printf '\t')
	# The live preview must match the tab even though the field holds raw \t.
	pdrive --tail '\x15' --tail '\\t' --tail '\r' --tail 'n\n' -- hello world -c -i "$td/f"
	if grep -q "f:1:-a${tab}b" "$td/out" && grep -q 'f:1:+aworldb' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: live preview did not show tab match. out=[$(cat "$td/out")]" > "$td/result"
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
	pdrive --tail '\r' --tail 'n\n' -- hello replacement -c -i "$td/f"
	if grep -q '1 matches, 1 files' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: stats not found. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_interactive_preview_truncated() {
	td=$1
	i=0
	while [ "$i" -lt 100 ]; do
		printf 'hello %s\n' "$i" >> "$td/f"
		i=$((i + 1))
	done
	# >52 matches in one file exceeds the match budget (max_preview_lines*4 =
	# 13*4 at 24 rows), so the per-keystroke scan must stop early: stats gain
	# the "+" suffix and the final reprint shows the omitted marker. Exercise
	# both the fixed-string and regex scan paths.
	pdrive --winsize 24x80 --tail '\r' --tail 'n\n' -- hello X -c -i -g "$td/f"
	fixed_plus=$(grep -c '+ matches' "$td/out")
	pdrive --winsize 24x80 --tail '\r' --tail 'n\n' -- 'hel.o' X -c -i -gR "$td/f"
	regex_plus=$(grep -c '+ matches' "$td/out")
	if [ "$fixed_plus" -gt 0 ] && [ "$regex_plus" -gt 0 ] && grep -q 'some previews omitted' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: truncation marker missing. fixed_plus=$fixed_plus regex_plus=$regex_plus out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_interactive_no_pre_tui_dump() {
	td=$1; printf 'hello world\n' > "$td/f"
	esc=$(printf '\033')
	# Pass 1 must only cache files for the interactive editor; the whole diff
	# must not be dumped to stdout before the TUI opens (which also stalled
	# startup with -g on a large tree). The alt-screen enter \x1b[?1049h is
	# the first thing the TUI emits, so any preview line before it is a dump.
	pdrive --tail '\x03' -- hello replacement -c -i "$td/f"
	if awk -v esc="$esc" -v out="$td/out" '
		{ buf = buf $0 "\n" }
		END {
			o = index(buf, esc "[?1049h")
			p = index(buf, "f:1:-hello")
			exit (o > 0 && p > o ? 0 : 1)
		}
	' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: preview leaked before TUI. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_interactive_height_capping() {
	td=$1; printf 'line 1\nline 2\nline 3\nline 4\nline 5\n' > "$td/f"
	pdrive --winsize 12x80 --tail '\r' --tail 'n\n' -- line replacement -c -i -g "$td/f"
	clean_out=$(sed 's/\x1b\[[0-9;]*m//g' "$td/out")
	# Count only the printed preview lines in raw interactive mode (marked by \x1b[K / [K)
	lines_count=$(grep '_interactive_height_capping/f' "$td/out" | grep -c '\[K')
	if printf '%s\n' "$clean_out" | grep -q 'some previews omitted' && [ "$lines_count" -le 3 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: height capping failed. lines=$lines_count out=[$clean_out]" > "$td/result"
	fi
}

t_confirm_interactive_tab_expansion() {
	td=$1; printf '\thello world\n' > "$td/f"
	tab=$(printf '\t')
	pdrive --winsize 24x80 --tail '\r' --tail 'n\n' -- hello replacement -c -i "$td/f"
	tui_out=$(grep '\[K' "$td/out")
	clean_tui=$(printf '%s\n' "$tui_out" | sed 's/\x1b\[[0-9;]*m//g; s/\x1b\[K//g; s/\[K//g')
	# Drop everything after the alt-screen teardown so the non-TUI post-session
	# preview (which echoes the file's raw tab) does not pollute the check.
	tui_render=$(printf '%s\n' "$clean_tui" | sed -E 's/\x1b\[\?1049l.*//')
	if printf '%s\n' "$tui_render" | grep -q ':-   hello world' && ! printf '%s\n' "$tui_render" | grep -Fq "$tab"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: tab expansion failed. tui=[$tui_render]" > "$td/result"
	fi
}

t_confirm_interactive_width_clipping() {
	td=$1
	dd if=/dev/zero bs=150 count=1 2>/dev/null | tr '\0' 'a' > "$td/f"
	printf '\n' >> "$td/f"
	pdrive --winsize 24x80 --tail '\r' --tail 'n\n' -- a b -c -i "$td/f"
	tui_out=$(grep '_interactive_width_clipping/f:1:-' "$td/out" | grep '\[K' | head -1)
	clean_line=$(printf '%s\n' "$tui_out" | sed -E 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\r//g')
	if [ -n "$clean_line" ] && [ "${#clean_line}" -le 79 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: width clipping failed. line_len=${#clean_line} line=[$clean_line]" > "$td/result"
	fi
}

t_confirm_vim_motions() {
	td=$1; printf 'hello world\n' > "$td/f"
	# Normal mode: 0 (home), l (right), x (delete char) -> find "hllo"
	# $ (end), X (delete before cursor) -> find "hll"
	# 0 (home), w (next word -> clamped to end), b (back to start)
	# Accept then abort so the file stays untouched; inspect the Find field.
	pdrive --phase 1b --phase 30@300 --phase 6c --phase 78 --phase 24 --phase 58 --phase 30 --phase 77 --phase 62 --phase 0d --tail 'n\n' -- hello replacement -c -i "$td/f"
	if [ "$(cat "$td/f")" = 'hello world' ] && grep -q 'Find:    hll' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim motions check failed. f=[$(cat "$td/f")] out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_vim_word_motions() {
	td=$1; printf 'hello world\n' > "$td/f"
	# Normal mode: 0 (home), w (next word), x (delete char), b (back), x
	pdrive --phase 1b --phase 30@200 --phase 77 --phase 78 --phase 62 --phase 78 --phase 0d --tail 'y\n' -- 'foo-bar baz' replacement -c -i "$td/f"
	if grep -q 'Find:    oobar baz' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim word motions check failed. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_vim_delete_eol() {
	td=$1; printf 'hell world\n' > "$td/f"
	# Normal mode: x deletes char at cursor (end of field -> last char)
	pdrive --phase 1b --phase 78@200 --phase 0d --tail 'y\n' -- hello replacement -c -i "$td/f"
	if grep -q 'Find:    hell' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim delete eol check failed. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_vim_delete_dd() {
	td=$1; printf 'hello world\n' > "$td/f"
	# Normal mode: dd (delete whole line), ihello (insert mode, re-type)
	pdrive --phase 1b --phase 6464@200 --phase 6968656c6c6f@200 --phase 0d --tail 'y\n' -- hello replacement -c -i "$td/f"
	if grep -q 'Find:    hello' "$td/out" && [ "$(cat "$td/f")" = 'replacement world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim dd check failed. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_vim_change_cw() {
	td=$1; printf 'qux-bar world\n' > "$td/f"
	# Normal mode: 0 (home), cwqux (change word to "qux")
	pdrive --phase 1b --phase 30@200 --phase 6377717578@200 --phase 0d --tail 'y\n' -- foo-bar replacement -c -i "$td/f"
	if grep -q 'Find:    qux-bar' "$td/out" && [ "$(cat "$td/f")" = 'replacement world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim cw check failed. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_interactive_include_exclude() {
	td=$1; mkdir -p "$td/d"
	printf 'hello\n' > "$td/d/a.txt"; printf 'hello\n' > "$td/d/b.txt"; printf 'hello\n' > "$td/d/c.c"
	# 4 tabs to Include, clear, set to "\\.txt$"; tab to Exclude, clear, set to "^b"
	pdrive --tail '\t\t\t\t\x15\.txt$\t\x15^b' --tail '\r' --tail 'y\n' -- hello HI -c -i -r "$td/d"
	ta=$(cat "$td/d/a.txt"); tb=$(cat "$td/d/b.txt"); tc=$(cat "$td/d/c.c")
	[ "$ta" = 'HI' ] && [ "$tb" = 'hello' ] && [ "$tc" = 'hello' ] && echo PASS > "$td/result" || echo "FAIL: a [$ta] b [$tb] c [$tc]" > "$td/result"
}

t_confirm_interactive_backup() {
	td=$1; printf 'hello\n' > "$td/f"
	# 6 tabs to Backup, clear, set to "bak"
	pdrive --tail '\t\t\t\t\t\t\x15bak' --tail '\r' --tail 'y\n' -- hello HI -c -i "$td/f"
	[ "$(cat "$td/f")" = 'HI' ] && [ "$(cat "$td/fbak")" = 'hello' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")] fbak=[$(cat "$td/fbak" 2>/dev/null)]" > "$td/result"
}

t_confirm_interactive_l_flag() {
	td=$1; printf 'hello\n' > "$td/f"
	# 2 tabs to Flags, clear, set to "l"
	pdrive --tail '\t\t\x15l' --tail '\r' --tail 'y\n' -- hello HI -c -i "$td/f"
	[ "$(cat "$td/f")" = 'HI' ] && grep -q "$td/f" "$td/out" && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")] path-not-printed" > "$td/result"
}

t_confirm_interactive_clear_filters() {
	td=$1; mkdir -p "$td/d"
	printf 'hello\n' > "$td/d/a.txt"; printf 'hello\n' > "$td/d/b.txt"
	# 4 tabs to Include, type "\\.txt$"; clear it (Ctrl-U); tab to Exclude,
	# type "^b"; clear it (Ctrl-U)
	pdrive --tail '\t\t\t\t\.txt$\x15\t^b\x15' --tail '\r' --tail 'y\n' -- hello HI -c -i -r "$td/d"
	ta=$(cat "$td/d/a.txt"); tb=$(cat "$td/d/b.txt")
	[ "$ta" = 'HI' ] && [ "$tb" = 'HI' ] && echo PASS > "$td/result" || echo "FAIL: a [$ta] b [$tb]" > "$td/result"
}

t_confirm_interactive_invalid_exclude() {
	td=$1; printf 'hello world\n' > "$td/f"
	# 5 tabs to Exclude, type invalid regex "[", abort with Ctrl-C
	pdrive --tail '\t\t\t\t\t[\x03' -- hello HI -c -i "$td/f"
	if grep -q 'Invalid Exclude regex' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: invalid exclude regex not reported. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_interactive_flags_ei() {
	td=$1; printf 'HeLLo world\n' > "$td/f"
	# 2 tabs to Flags, clear, set to "EIz" (extended + icase regex, -z)
	pdrive --tail '\t\t\x15EIz' --tail '\r' --tail 'y\n' -- hello HI -c -i "$td/f"
	[ "$(cat "$td/f")" = 'HI world' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")]" > "$td/result"
}

t_vim_normal_mode_word_motions() {
	td=$1; printf 'foo bar az\n' > "$td/f"
	# ESC then vim motions: 0 w w x b w w
	pdrive --phase 1b --phase 30@300 --phase 77 --phase 77 --phase 78 --phase 62 --phase 77 --phase 77 --phase 0d --tail 'y\n' -- 'foo bar baz' X -c -i "$td/f"
	if [ "$(cat "$td/rc")" = 0 ] && [ "$(cat "$td/f")" = 'X' ] && grep -q 'Find:    foo bar az' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=[$(cat "$td/rc")] f=[$(cat "$td/f")] out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

t_vim_delete_ops() {
	td=$1
	good=1
	# dw: 0 d w -> find "bar baz"
	printf 'foo bar baz\n' > "$td/f1"
pdrive --phase 1b --phase 30@300 --phase 64 --phase 77 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f1"
	[ "$(cat "$td/f1")" = 'foo X' ] || good=0
	# db: $ d b -> find "foo bar z" (no match, cursor clamps to end-1)
	printf 'foo bar baz\n' > "$td/f2"
pdrive --phase 1b --phase 24@300 --phase 64 --phase 62 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f2"
	[ "$(cat "$td/f2")" = 'foo bar baz' ] || good=0
	# d0: $ d 0 -> find "z"
	printf 'foo bar baz\n' > "$td/f3"
pdrive --phase 1b --phase 24@300 --phase 64 --phase 30 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f3"
	[ "$(cat "$td/f3")" = 'foo bar baX' ] || good=0
	# d0: b d 0 -> find "baz"
	printf 'foo bar baz\n' > "$td/f4"
pdrive --phase 1b --phase 62@300 --phase 64 --phase 30 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f4"
	[ "$(cat "$td/f4")" = 'foo bar X' ] || good=0
	# d$: 0 d $ -> find empty, no matches, file untouched
	printf 'foo bar baz\n' > "$td/f5"
pdrive --phase 1b --phase 30@300 --phase 64 --phase 24 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f5"
	[ "$(cat "$td/f5")" = 'foo bar baz' ] || good=0
	# dd: 0 d d -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f6"
pdrive --phase 1b --phase 30@300 --phase 64 --phase 64 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f6"
	[ "$(cat "$td/f6")" = 'foo bar baz' ] || good=0
	# x: 0 x -> delete first char -> find "oo bar baz"
	printf 'foo bar baz\n' > "$td/f7"
pdrive --phase 1b --phase 30@300 --phase 78 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f7"
	[ "$(cat "$td/f7")" = 'fX' ] || good=0
	# X: $ X -> delete char before end cursor -> find "foo bar bz" (no match)
	printf 'foo bar baz\n' > "$td/f8"
pdrive --phase 1b --phase 24@300 --phase 58 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f8"
	[ "$(cat "$td/f8")" = 'foo bar baz' ] || good=0
	# D: 0 D -> delete to end -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f9"
pdrive --phase 1b --phase 30@300 --phase 44 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f9"
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
pdrive --phase 1b --phase 30@300 --phase 63 --phase 77 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f1"
	[ "$(cat "$td/f1")" = 'foo X' ] || good=0
	# cb: 0 c b -> no-op (cursor at 0), find unchanged
	printf 'foo bar baz\n' > "$td/f2"
pdrive --phase 1b --phase 30@300 --phase 63 --phase 62 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f2"
	[ "$(cat "$td/f2")" = 'X' ] || good=0
	# c0: $ c 0 -> find "z"
	printf 'foo bar baz\n' > "$td/f3"
pdrive --phase 1b --phase 24@300 --phase 63 --phase 30 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f3"
	[ "$(cat "$td/f3")" = 'foo bar baX' ] || good=0
	# c$: 0 c $ -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f4"
pdrive --phase 1b --phase 30@300 --phase 63 --phase 24 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f4"
	[ "$(cat "$td/f4")" = 'foo bar baz' ] || good=0
	# cc: 0 c c -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f5"
pdrive --phase 1b --phase 30@300 --phase 63 --phase 63 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f5"
	[ "$(cat "$td/f5")" = 'foo bar baz' ] || good=0
	# C: 0 w C -> find "foo ", file "Xbar baz"
	printf 'foo bar baz\n' > "$td/f6"
pdrive --phase 1b --phase 30@300 --phase 77 --phase 43 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f6"
	[ "$(cat "$td/f6")" = 'Xbar baz' ] || good=0
	# C: 0 C -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f7"
pdrive --phase 1b --phase 30@300 --phase 43 --phase 0d --tail 'y\n' -- 'foo bar baz' 'X' -c -i "$td/f7"
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
pdrive --phase 1b --phase 49@300 --phase 58 --phase 0d --tail 'y\n' -- 'hello' 'R' -c -i "$td/f1"
	[ "$(cat "$td/f1")" = 'R world' ] || good=0
	# A: insert at end -> find "helloX"
	printf 'helloX world\n' > "$td/f2"
pdrive --phase 1b --phase 41@300 --phase 58 --phase 0d --tail 'y\n' -- 'hello' 'R' -c -i "$td/f2"
	[ "$(cat "$td/f2")" = 'R world' ] || good=0
	# 0 l i: insert at cursor 1 -> find "hXello"
	printf 'hXello world\n' > "$td/f3"
pdrive --phase 1b --phase 30@300 --phase 6c --phase 69 --phase 58 --phase 0d --tail 'y\n' -- 'hello' 'R' -c -i "$td/f3"
	[ "$(cat "$td/f3")" = 'R world' ] || good=0
	# 0 l a: append after cursor -> find "heXllo"
	printf 'heXllo world\n' > "$td/f4"
pdrive --phase 1b --phase 30@300 --phase 6c --phase 61 --phase 58 --phase 0d --tail 'y\n' -- 'hello' 'R' -c -i "$td/f4"
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
pdrive --phase 1b --phase 6a@300 --phase 69 --phase 7a --phase 7a --phase 0d --tail 'y\n' -- 'hello' 'replacement' -c -i "$td/f1"
	[ "$(cat "$td/f1")" = 'replacemenzzt world' ] || good=0
	# k k j: up to Backup (wrap), down to Exclude... then j to Backup, type bak suffix
	printf 'hello world\n' > "$td/f2"
pdrive --phase 1b --phase 6b@300 --phase 6b --phase 6a --phase 69 --phase 62616b --phase 0d --tail 'y\n' -- 'hello' 'replacement' -c -i "$td/f2"
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
	pdrive --env LINES= --tail '\r' --tail 'y\n' -- X Y -c -i -g "$td/f"
	yg=$(tr -cd 'Y' < "$td/f" | wc -c)
	if [ "$(cat "$td/rc")" = 0 ] && [ "$yg" -eq 20 ] && grep -q '20 matches, 1 files' "$td/out" && grep -q 'some previews omitted' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=[$(cat "$td/rc")] yg=$yg out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

t_terminal_cols_env() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --env COLUMNS=30 --tail '\r' --tail 'y\n' -- hello HI -c -i "$td/f"
	if [ "$(cat "$td/rc")" = 0 ] && [ "$(cat "$td/f")" = 'HI world' ] && grep -q '1 matches, 1 files' "$td/out" && grep -q 'Find:    hello' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=[$(cat "$td/rc")] f=[$(cat "$td/f")] out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

t_interactive_signal_term() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --signal TERM -- hello HI -c -i "$td/f"
	if [ "$(cat "$td/rc")" = 1 ] && [ "$(cat "$td/f")" = 'hello world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=[$(cat "$td/rc")] file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_interactive_file_deleted_rename_fail() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --after-ready "rm '$td/f' && mkdir '$td/f'" --tail '\r' --tail 'y\n' -- hello bye -c -i "$td/f"
	[ "$(cat "$td/rc")" = 1 ] && grep -q 'rename temp file' "$td/out" && echo PASS > "$td/result" || echo "FAIL: rc=[$(cat "$td/rc")]" > "$td/result"
}

t_interactive_invalid_flag_char() {
	td=$1; printf 'hello world\n' > "$td/f"
	# 2 tabs to Flags, clear, type invalid flag char "x"
	pdrive --tail '\t\t\x15x' --tail '\r' --tail 'n\n' -- hello HI -c -i "$td/f"
	if [ "$(cat "$td/rc")" = 1 ] && grep -q 'Flags:   x' "$td/out" && [ "$(cat "$td/f")" = 'hello world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=[$(cat "$td/rc")] out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

t_interactive_arrows() {
	td=$1
	good=1
	# up, down, right, left, right (restore cursor), shift-tab, delete, shift-tab,
	# down, down (back to Find), type X -> find "helloX"
	printf 'helloX world\n' > "$td/f1"
pdrive --phase 1b5b41 --phase 1b5b42@250 --phase 1b5b43@250 --phase 1b5b44@250 --phase 1b5b43@250 --phase 1b5b5a@250 --phase 1b5b337e@250 --phase 1b5b5a@250 --phase 1b5b42@250 --phase 1b5b42@250 --phase 58@250 --phase 0d --tail 'y\n' -- 'hello' 'replacement' -c -i "$td/f1"
	[ "$(cat "$td/f1")" = 'replacement world' ] || good=0
	# ESC 0 then Delete key in normal mode deletes first char -> find "ello"
	printf 'hello world\n' > "$td/f2"
pdrive --phase 1b --phase 30@250 --phase 1b5b337e@250 --phase 0d --tail 'y\n' -- 'hello' 'replacement' -c -i "$td/f2"
	[ "$(cat "$td/f2")" = 'hreplacement world' ] || good=0
	if [ "$good" -eq 1 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")]" > "$td/result"
	fi
}

t_interactive_ctrl_j_k() {
	td=$1; printf 'hello world\n' > "$td/f"
	# Ctrl-J down (Replace), Ctrl-J down (Flags), Ctrl-K up (Replace), type zz
pdrive --phase 0a --phase 0a@250 --phase 0b@250 --phase 7a@250 --phase 7a@250 --phase 0d --tail 'y\n' -- 'hello' 'replacement' -c -i "$td/f"
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
	# dd empties the find field; no matches -> no prompt, file untouched
pdrive --phase 1b --phase 64@300 --phase 64 --phase 0d --tail 'n\n' -- 'foo bar' 'X' -c -i "$td/f"
	[ "$(cat "$td/f")" = 'foo bar baz' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")]" > "$td/result"
}

t_confirm_abstractions() {
	td=$1; printf 'hello abstractions\n' > "$td/f"
pdrive --phase 0a --phase 2121 --phase 0b --phase 0d --tail 'y\n' -- hello world -c -i "$td/f"
	[ "$(cat "$td/f")" = 'world!! abstractions' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")]" > "$td/result"
}

t_confirm_interactive_controls_fixed() {
	td=$1; printf 'hello world\n' > "$td/f"
	# Short preview must not push the controls down with it: on a 24-row
	# screen the control block is anchored so Find (field 0) sits at row
	# 18 and the last field ends on row 24. Assert the render jumps the
	# cursor to the [INSERT] row (16) and to the Find field (18;17).
	pdrive --winsize 24x80 --tail '\r' --tail 'n\n' -- hello HI -c -i "$td/f"
	if grep -q '\[16;1H' "$td/out" && grep -q '\[18;17H' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: controls not pinned to bottom. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

t_confirm_interactive_no_scroll() {
	td=$1
	i=1; : > "$td/f"
	while [ $i -le 20 ]; do printf 'line %d hello\n' "$i" >> "$td/f"; i=$((i + 1)); done
	pdrive --winsize 24x80 --tail '\r' --tail 'n\n' -- hello world -c -i -g "$td/f"
	# Take the last full screen (after the last clear-screen+home). The
	# preview is capped at 13 lines (24 rows minus 11 control rows), the
	# omitted marker follows, and then the render jumps to the pinned
	# controls header at row 16. 14 = 13 preview lines + omitted marker.
	frame=$(awk 'BEGIN{RS="\x1b\\[2J\x1b\\[H"} {last=$0} END{print last}' "$td/out")
	res=$(printf '%s' "$frame" | awk 'BEGIN{RS="\x1b\\[[0-9]+;[0-9]+H"} {print gsub("\n","&"); exit}')
	if [ "$res" = "14" ] && printf '%s' "$frame" | grep -q '\[16;1H'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: terminal scrolled during interactive render (newlines=$res)" > "$td/result"
	fi
}

t_confirm_match_consumes_newline() {
	td=$1; printf 'a\nb\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" 'a\n' 'X' -c -i -R "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	if [ "$(cat "$td/f")" = 'Xb' ] && printf '%s\n' "$clean_out" | grep -q -- '-a' && printf '%s\n' "$clean_out" | grep -q -- '+X'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
	fi
}

t_confirm_empty_replace_line() {
	td=$1; printf 'a\nb\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" b '' -c -i "$td/f" 2>/dev/null)
	if [ "$(cat "$td/f")" = 'a' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_confirm_regex_match_at_eof() {
	td=$1; printf 'ab\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" 'b$' 'X' -c -i -R "$td/f" 2>/dev/null)
	if [ "$(cat "$td/f")" = 'aX' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_confirm_interactive_ctrl_d() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --phase 04 -- hello HI -c -i "$td/f"
	if [ "$(cat "$td/rc")" = 1 ] && [ "$(cat "$td/f")" = 'hello world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=[$(cat "$td/rc")] file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_confirm_interactive_unknown_escape() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --phase 1b5b58 --phase 04@300 -- hello HI -c -i "$td/f"
	if [ "$(cat "$td/rc")" = 1 ] && [ "$(cat "$td/f")" = 'hello world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=[$(cat "$td/rc")] file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_confirm_interactive_control_char() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --phase 01 --phase 04@300 -- hello HI -c -i "$td/f"
	if [ "$(cat "$td/rc")" = 1 ] && [ "$(cat "$td/f")" = 'hello world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=[$(cat "$td/rc")] file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_confirm_interactive_cli_flags() {
	td=$1; printf 'HELLO world\n' > "$td/f"
	pdrive --tail '\r' --tail 'y\n' -- hello HI -c -i -R -E -I -z -l "$td/f"
	if [ "$(cat "$td/f")" = 'HI world' ] && grep -q -- 'Flags:   GREIzl' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: file=[$(cat "$td/f")] out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

t_confirm_interactive_cli_filters_backup() {
	td=$1; printf 'hello world\n' > "$td/hello.txt"; printf 'hello world\n' > "$td/x.log"
	pdrive --tail '\r' --tail 'y\n' -- hello HI -c -ibak --include '\.txt$' --exclude '^x' "$td/hello.txt" "$td/x.log"
	if [ "$(cat "$td/hello.txt")" = 'HI world' ] && [ "$(cat "$td/hello.txtbak")" = 'hello world' ] && [ "$(cat "$td/x.log")" = 'hello world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: txt=[$(cat "$td/hello.txt")] bak=[$(cat "$td/hello.txtbak" 2>/dev/null)] log=[$(cat "$td/x.log")]" > "$td/result"
	fi
}

t_confirm_interactive_files_filter() {
	td=$1; printf 'hello\n' > "$td/f1.txt"; printf 'hello\n' > "$td/f2.log"
	pdrive --phase 09 --phase 09 --phase 09 --phase 66@200 --phase 31@200 --phase 0d --tail 'y\n' -- hello HI -c -i "$td/f1.txt" "$td/f2.log"
	if [ "$(cat "$td/f1.txt")" = 'HI' ] && [ "$(cat "$td/f2.log")" = 'hello' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: f1=[$(cat "$td/f1.txt")] f2=[$(cat "$td/f2.log")]" > "$td/result"
	fi
}

t_confirm_interactive_enter_invalid() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --phase 0d --phase 04@300 -- '[' HI -c -i -R "$td/f"
	if [ "$(cat "$td/rc")" = 1 ] && [ "$(cat "$td/f")" = 'hello world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=[$(cat "$td/rc")] file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_confirm_interactive_tiny_terminal() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --winsize 1x40 --tail '\r' --tail 'y\n' -- hello HI -c -i "$td/f"
	if [ "$(cat "$td/rc")" = 0 ] && [ "$(cat "$td/f")" = 'HI world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=[$(cat "$td/rc")] file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_vim_word_punct_forward() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --phase 1b --phase 30@300 --phase 77 --phase 78 --phase 04@300 -- '#foo' x -c -i "$td/f"
	if [ "$(cat "$td/f")" = 'hello world' ] && grep -q -- 'Find:    #oo' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: find line not as expected; file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_vim_word_punct_backward() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --phase 1b --phase 24@300 --phase 62 --phase 78 --phase 04@300 -- 'foo--x' x -c -i "$td/f"
	if [ "$(cat "$td/f")" = 'hello world' ] && grep -q -- 'Find:    foo-x' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: find line not as expected; file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_vim_w_empty_field() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --phase 1b --phase 04@300 -- 'hello' x -c -i "$td/f"
	if [ "$(cat "$td/f")" = 'hello world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_vim_dw_clamp() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --phase 1b --phase 30@300 --phase 77 --phase 64 --phase 77 --phase 04@300 -- 'hello world' x -c -i "$td/f"
	if [ "$(cat "$td/f")" = 'hello world' ] && grep -q -- 'Find:    hello' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: find line not as expected; file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_vim_ddollar_clamp() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --phase 1b --phase 24@300 --phase 64 --phase 24 --phase 04@300 -- 'abc' x -c -i "$td/f"
	if [ "$(cat "$td/f")" = 'hello world' ] && grep -q -- 'Find:    ab' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: find line not as expected; file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_vim_D_clamp() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --phase 1b --phase 24@300 --phase 44 --phase 04@300 -- 'abc' x -c -i "$td/f"
	if [ "$(cat "$td/f")" = 'hello world' ] && grep -q -- 'Find:    ab' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: find line not as expected; file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_vim_h_and_default() {
	td=$1; printf 'hello world\n' > "$td/f"
	pdrive --phase 1b --phase 71@300 --phase 68 --phase 78 --phase 04@300 -- 'hello' x -c -i "$td/f"
	if [ "$(cat "$td/f")" = 'hello world' ] && grep -q -- 'Find:    helo' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: find line not as expected; file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_confirm_grep_interactive() {
	td=$1; printf 'hello world\nfoo bar\n' > "$td/f"
	pdrive --tail '\r' -- hello --grep -c "$td/f"
	clean_out=$(sed 's/\x1b\[[0-9;]*m//g' "$td/out")
	if printf '%s\n' "$clean_out" | grep -q 'hello world' && [ "$(cat "$td/f")" = 'hello world
foo bar' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: grep interactive check failed. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

TESTS="
t_confirm_yes
t_confirm_colored_default
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
t_confirm_interactive_escape_find
t_confirm_interactive_escape_replace
t_confirm_interactive_escape_live_preview
t_confirm_non_interactive_backref_mismatch
t_confirm_interactive_stats
t_confirm_interactive_preview_truncated
t_confirm_interactive_no_pre_tui_dump
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
t_confirm_interactive_controls_fixed
t_confirm_match_consumes_newline
t_confirm_empty_replace_line
t_confirm_regex_match_at_eof
t_confirm_interactive_ctrl_d
t_confirm_interactive_unknown_escape
t_confirm_interactive_control_char
t_confirm_interactive_cli_flags
t_confirm_interactive_cli_filters_backup
t_confirm_interactive_files_filter
t_confirm_interactive_enter_invalid
t_confirm_interactive_tiny_terminal
t_vim_word_punct_forward
t_vim_word_punct_backward
t_vim_w_empty_field
t_vim_dw_clamp
t_vim_ddollar_clamp
t_vim_D_clamp
t_vim_h_and_default
t_confirm_grep_interactive
"

run_suite "confirm tests" "$TESTS"
