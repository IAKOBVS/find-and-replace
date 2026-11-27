#!/bin/sh
PROG_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$PROG_DIR/tests/lib.sh"

PDRV="$PROG_DIR/tests/pty_drive"

# pdrive [--out FILE] [--rc FILE] [--noready] [--phase HEX[@MS] ...] [--tail TEXT] -- [tool args...]
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
	"$PDRV" --prog "$PROG" --out "$td/out" --rc "$td/rc" "$@" >/dev/null 2>&1
}

strip_ansi() {
	sed 's/\x1b\[[0-9;]*m//g'
}

t_grep_stdin() {
	td=$1
	printf 'hello\nworld\n' | "$PROG" hello there --grep > "$td/out" 2>/dev/null
	rc=$?
	out=$(strip_ansi < "$td/out")
	[ "$rc" -eq 0 ] && [ "$out" = '1:hello' ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out]" > "$td/result"
}

t_grep_no_match() {
	td=$1
	printf 'hello\n' | "$PROG" xyz there --grep > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 1 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc" > "$td/result"
}

t_grep_exit_2_bad_regex() {
	td=$1
	printf 'hello\n' | "$PROG" '[' there --grep -R > /dev/null 2>&1
	rc=$?
	[ "$rc" -eq 2 ] && echo PASS > "$td/result" || echo "FAIL: bad regex should exit 2 (rc=$rc)" > "$td/result"
}

t_grep_conflict_i() {
	td=$1
	printf 'x\n' | "$PROG" x y --grep -i > /dev/null 2>&1
	rc=$?
	[ "$rc" -eq 2 ] && echo PASS > "$td/result" || echo "FAIL: --grep with -i should exit 2 (rc=$rc)" > "$td/result"
}

t_grep_conflict_c() {
	td=$1
	printf 'x\n' > "$td/f"
	"$PROG" x y --grep -c -i "$td/f" > /dev/null 2>&1
	rc=$?
	[ "$rc" -eq 2 ] && echo PASS > "$td/result" || echo "FAIL: --grep with -c should exit 2 (rc=$rc)" > "$td/result"
}

t_grep_single_file_prefix() {
	td=$1
	printf 'foo\n' > "$td/f"
	"$PROG" foo bar --grep "$td/f" > "$td/out" 2>/dev/null
	rc=$?
	exp="$td/f:1:foo"
	out=$(strip_ansi < "$td/out")
	[ "$rc" -eq 0 ] && [ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out] exp=[$exp]" > "$td/result"
}

t_grep_multiple_files() {
	td=$1
	printf 'foo\n' > "$td/f1"; printf 'foo\n' > "$td/f2"
	"$PROG" foo bar --grep "$td/f1" "$td/f2" > "$td/out" 2>/dev/null
	out=$(strip_ansi < "$td/out")
	exp="$td/f1:1:foo
$td/f2:1:foo"
	[ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: out=[$out] exp=[$exp]" > "$td/result"
}

t_grep_recursive() {
	td=$1; mkdir -p "$td/sub"
	printf 'match\n' > "$td/sub/a.txt"; printf 'nomatch\n' > "$td/sub/b.c"; printf 'match\n' > "$td/sub/c.txt"
	"$PROG" match M --grep -r --include '\.txt$' "$td/sub" > "$td/out" 2>/dev/null
	rc=$?
	out=$(strip_ansi < "$td/out" | sort)
	exp="$td/sub/a.txt:1:match
$td/sub/c.txt:1:match"
	[ "$rc" -eq 0 ] && [ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out] exp=[$exp]" > "$td/result"
}

t_grep_regex_anchor() {
	td=$1
	printf 'alpha\nbeta\nalpha\n' | "$PROG" '^alpha' '' --grep -R > "$td/out" 2>/dev/null
	rc=$?
	exp='1:alpha
3:alpha'
	out=$(strip_ansi < "$td/out")
	[ "$rc" -eq 0 ] && [ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out] exp=[$exp]" > "$td/result"
}

t_grep_fixed() {
	td=$1
	printf 'apple\nbanana\n' | "$PROG" app x --grep > "$td/out" 2>/dev/null
	rc=$?
	out=$(strip_ansi < "$td/out")
	[ "$rc" -eq 0 ] && [ "$out" = '1:apple' ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out]" > "$td/result"
}

t_grep_empty_find() {
	td=$1
	printf 'a\nb\n' | "$PROG" '' x --grep > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 0 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc" > "$td/result"
}

t_grep_empty_find_dash() {
	td=$1
	printf 'a\n' | "$PROG" '' x --grep - > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 0 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc" > "$td/result"
}

t_grep_empty_find_file() {
	td=$1
	printf 'abc\n' > "$td/f"
	"$PROG" '' x --grep "$td/f" > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 0 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc" > "$td/result"
}

t_grep_empty_input() {
	td=$1
	: | "$PROG" foo bar --grep > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 1 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc" > "$td/result"
}

t_grep_quiet() {
	td=$1
	printf 'hello\n' | "$PROG" hello x --grep -q > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 0 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc" > "$td/result"
}

t_grep_binary() {
	td=$1
	printf 'ab\000cd' > "$td/bin"
	"$PROG" ab x --grep "$td/bin" > "$td/out" 2>/dev/null
	rc=$?
	[ "$rc" -eq 1 ] && [ ! -s "$td/out" ] && echo PASS > "$td/result" || echo "FAIL: binary file should be skipped (rc=$rc)" > "$td/result"
}

t_grep_dash_stdin_placeholder() {
	td=$1
	printf 'match one\n' > "$td/f1"; printf 'match three\n' > "$td/f2"
	printf 'match two\n' > "$td/sin"
	"$PROG" match M --grep "$td/f1" - "$td/f2" < "$td/sin" > "$td/out" 2>/dev/null
	rc=$?
	exp="$td/f1:1:match one
1:match two
$td/f2:1:match three"
	out=$(strip_ansi < "$td/out")
	[ "$rc" -eq 0 ] && [ "$out" = "$exp" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc out=[$out] exp=[$exp]" > "$td/result"
}

t_grep_exclude_cli() {
	td=$1
	printf 'keep\n' > "$td/k.txt"; printf 'ignore\n' > "$td/i.txt"
	"$PROG" keep x --grep --exclude '^i' "$td/k.txt" "$td/i.txt" > "$td/out" 2>/dev/null
	out=$(strip_ansi < "$td/out")
	[ "$out" = "$td/k.txt:1:keep" ] && echo PASS > "$td/result" || echo "FAIL: out=[$out]" > "$td/result"
}

t_grep_nonexistent_file() {
	td=$1
	"$PROG" foo bar --grep "$td/nope" > /dev/null 2>&1
	rc=$?
	[ "$rc" -eq 2 ] && echo PASS > "$td/result" || echo "FAIL: nonexistent file in --grep should exit 2 (rc=$rc)" > "$td/result"
}

t_grep_interactive_invalid_find() {
	td=$1; mkdir -p "$td/sub"
	printf 'hit\n' > "$td/sub/a.txt"
	pdrive --phase 15 --phase 5b@50 --phase 03@400 -- hit x --grep -r "$td/sub"
	case "$(cat "$td/rc")" in sig:*|timeout) echo "FAIL: abnormal rc=$(cat "$td/rc")" > "$td/result" ;; *) echo PASS > "$td/result" ;; esac
}

t_grep_interactive_invalid_include() {
	td=$1; mkdir -p "$td/sub"
	printf 'hit\n' > "$td/sub/a.txt"
	pdrive --phase 09 --phase 09@50 --phase 5b@50 --phase 03@400 -- hit x --grep -r "$td/sub"
	case "$(cat "$td/rc")" in sig:*|timeout) echo "FAIL: abnormal rc=$(cat "$td/rc")" > "$td/result" ;; *) echo PASS > "$td/result" ;; esac
}

t_grep_interactive_invalid_exclude() {
	td=$1; mkdir -p "$td/sub"
	printf 'hit\n' > "$td/sub/a.txt"
	pdrive --phase 09 --phase 09@50 --phase 09@50 --phase 5b@50 --phase 03@400 -- hit x --grep -r "$td/sub"
	case "$(cat "$td/rc")" in sig:*|timeout) echo "FAIL: abnormal rc=$(cat "$td/rc")" > "$td/result" ;; *) echo PASS > "$td/result" ;; esac
}

t_grep_interactive_regex() {
	td=$1
	printf 'hello\nworld\n' > "$td/f"
	pdrive --noready --phase 0d --tail '' -- 'hel+' x --grep -R -E "$td/f"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF '1:hello'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

t_grep_interactive_recursive() {
	td=$1; mkdir -p "$td/sub"
	printf 'hello one\n' > "$td/sub/a"
	printf 'hello two\n' > "$td/sub/b"
	pdrive --noready --phase 0d --tail '' -- hello x --grep -r "$td/sub"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF 'hello one' || printf '%s\n' "$out" | grep -qF 'hello two'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

t_grep_interactive_basic() {
	td=$1
	printf 'hello\nworld\nfoo\n' > "$td/f"
	# Start grep TUI, press Enter immediately (selects first match "hello")
pdrive --noready --phase 0d --tail '' -- hello x --grep "$td/f"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF '1:hello'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

t_grep_interactive_scroll() {
	td=$1
	printf 'aaa\naba\naca\n' > "$td/f"
	pdrive --phase 1b6a --phase 0d --tail '' -- 'a' x --grep "$td/f"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF '2:aba'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

t_grep_interactive_deep_scroll_overdraw() {
	td=$1
	i=0
	while [ "$i" -lt 40 ]; do
		i=$((i + 1))
		printf 'm%02d\n' "$i"
	done > "$td/f"
	keys=
	i=0
	while [ "$i" -lt 30 ]; do
		keys="${keys}1b4a"
		i=$((i + 1))
	done
	pdrive --phase "${keys}@50" --phase '0d@100' --tail '' -- m x --grep "$td/f"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF '15:m15' &&
	   ! printf '%s\n' "$out" | grep -qF '39:m39'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

t_grep_interactive_ctrl_j_k_nav() {
	td=$1
	printf 'hello\nworld\n' > "$td/f"
	# Start grep TUI, Ctrl-J moves down to Files field, Ctrl-K moves back up to Find field, Enter
pdrive --phase 0a --phase 0b@150 --phase 0d --tail '' -- hello x --grep "$td/f"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF '1:hello'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

t_grep_interactive_exclude() {
	td=$1
	printf 'alpha\nbeta\ngamma\n' > "$td/f1"
	printf 'alpha2\nbeta2\n' > "$td/f2"
	# Start grep TUI with --exclude matching f1, only f2 should appear
pdrive --noready --phase 0d --tail '' -- alpha x --grep --exclude 'f1$' "$td/f1" "$td/f2"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF 'f2:' && ! printf '%s\n' "$out" | grep -qF 'f1:'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

t_grep_interactive_ctrl_d() {
	td=$1
	printf 'hello\n' > "$td/f"
	pdrive --phase 04 --tail '' -- hello x --grep "$td/f"
	out=$(strip_ansi < "$td/out")
	rc=$(cat "$td/rc" 2>/dev/null)
	if printf '%s\n' "$out" | grep -qF 'Aborted.' && [ -n "$rc" ] && [ "$rc" -ne 0 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc out=[$out]" > "$td/result"
	fi
}

t_grep_interactive_multiline() {
	td=$1
	printf 'line1\nline2\nline3\nline4\nline5\n' > "$td/f"
	# Enter with first match selected, should print it
pdrive --noready --phase 0d --tail '' -- line x --grep "$td/f"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF '1:line1'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

# Regression: G.grep_collect was set AFTER the file loop, so process_file
# never cached files and the TUI opened with 0 matches.  Verify that files
# on the command line are cached and the TUI shows correct match stats.
t_grep_interactive_file_cache() {
	td=$1
	printf 'aaa\nbbb\naaa\n' > "$td/f1"
	printf 'ccc\naaa\n' > "$td/f2"
pdrive --phase 0d --tail '' -- aaa x --grep "$td/f1" "$td/f2"
	out=$(strip_ansi < "$td/out")
	# Must have entered TUI (the marker was seen) and stats must show 3 matches 2 files
	# Line numbers are per-file: f1:1 aaa, f1:3 aaa, f2:2 aaa
	if printf '%s\n' "$out" | grep -qF '3 matches, 2 files' && \
	   printf '%s\n' "$out" | grep -qF 'f1:1:aaa' && \
	   printf '%s\n' "$out" | grep -qF 'f1:3:aaa' && \
	   printf '%s\n' "$out" | grep -qF 'f2:2:aaa'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

# Regression: grep TUI was missing a FIND field — user could not change
# the find string interactively.  Verify the TUI renders "Find:" and the
# initial find value is shown.
t_grep_interactive_find_field() {
	td=$1
	printf 'hello world\nfoo bar\n' > "$td/f"
pdrive --noready --phase 0d --tail '' -- hello x --grep "$td/f"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF 'Find:' && \
	   printf '%s\n' "$out" | grep -qF 'hello'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

# Regression: grep TUI controls floated after the preview instead of being
# pinned to the bottom.  Verify the render jumps to a fixed row (the
# terminal's last field row) via cursor-move escape.
t_grep_interactive_controls_fixed() {
	td=$1
	printf 'hello world\n' > "$td/f"
	# 4 fields + 3 control lines = 7; on a 24-row terminal the
	# start_control_line = 24 - (4 + 1) = 19, so [INSERT] is at row 19.
pdrive --winsize 24x80 --noready --phase 0d --tail '' -- hello x --grep "$td/f"
	if grep -q '\[19;1H' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: controls not pinned. out=[$(cat "$td/out")]" > "$td/result"
	fi
}

# Regression: grep TUI always showed "[INSERT]" and never switched to
# "[NORMAL]" on Esc.  Verify Esc toggles the label, then Enter exits.
t_grep_interactive_vim_mode() {
	td=$1
	printf 'hello world\n' > "$td/f"
	# --noready sends all phases immediately; Esc enters NORMAL mode,
	# Enter exits.  Use @2000d (200ms delay before Enter) so the ESC
	# parser's 100ms VTIME window expires before the Enter byte arrives;
	# otherwise the ESC handler consumes Enter as part of the sequence.
pdrive --noready --phase 1b --phase 0d@200 --tail '' -- hello x --grep "$td/f"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF '[INSERT]' && \
	   printf '%s\n' "$out" | grep -qF '[NORMAL]'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

t_grep_interactive_no_blank_while_typing() {
	td=$1
	for i in $(seq 1 200); do printf 'hello line %s\n' "$i"; done > "$td/f"
	pdrive --phase 15 --phase 61@50 --phase 62@50 --phase 63@50 \
	       --phase 04@50 --tail '' -- hello x --grep "$td/f"
	out=$(strip_ansi < "$td/out")
	after=$(printf '%s\n' "$out" | awk '/200 matches, 1 files/{seen=1; next} seen')
	if printf '%s\n' "$after" | grep -qF '0 matches, 0 files'; then
		echo "FAIL: blanked while typing: out=[$out]" > "$td/result"
	else
		echo PASS > "$td/result"
	fi
}

t_grep_interactive_blank_after_debounce() {
	td=$1
	for i in $(seq 1 20); do printf 'hello line %s\n' "$i"; done > "$td/f"
	pdrive --phase 15 --phase 04@300 --tail '' -- hello x --grep "$td/f"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF '0 matches, 0 files' && \
	   printf '%s\n' "$out" | grep -qF '20 matches, 1 files'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

t_grep_interactive_large_batch() {
	td=$1
	for i in $(seq 1 200); do printf 'hello line %s\n' "$i"; done > "$td/f"
	pdrive --phase 0d --tail '' -- hello x --grep "$td/f"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF '200 matches, 1 files' && \
	   printf '%s\n' "$out" | grep -qF '1:hello line 1'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

# Regression: regex grep sliced the buffer at a zero-length line but the
# regex engine was given the NUL-terminated buffer position, so it matched
# into later lines and produced offsets larger than the line. That underflowed
# ui_format_grep_line's tail length and corrupted the heap.
t_grep_regex_empty_lines() {
	td=$1
	printf 'foo\n\nbar\n' > "$td/f"
	rc=0
	out=$("$PROG" '.' x -R --grep -j 1 "$td/f" 2>/dev/null) || rc=$?
	out=$(printf '%s\n' "$out" | strip_ansi)
	n=$(printf '%s\n' "$out" | grep -c . || true)
	if [ "$rc" -eq 0 ] && [ "$n" -eq 2 ] && \
	   printf '%s\n' "$out" | grep -qF 'foo' && \
	   printf '%s\n' "$out" | grep -qF 'bar'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc out=[$out]" > "$td/result"
	fi
}

t_grep_regex_empty_line_anchor() {
	td=$1
	printf 'foo\n\nbar\n' > "$td/f"
	rc=0
	out=$("$PROG" '^$' x -R --grep -j 1 "$td/f" 2>/dev/null) || rc=$?
	out=$(printf '%s\n' "$out" | strip_ansi)
	if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -qF ':2:'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc out=[$out]" > "$td/result"
	fi
}

t_grep_files_field_rescan() {
	td=$1; mkdir -p "$td/sub"
	printf 'hit\n' > "$td/sub/a.txt"
	printf 'hit\n' > "$td/sub/b.txt"
	pdrive --phase 0a --phase 15@50 --phase 61@50 --phase 2e@50 --phase 74@50 --phase 78@50 --phase 74@50 \
	       --phase 0d@400 --tail '' -- hit x --grep -r "$td/sub"
	out=$(strip_ansi < "$td/out")
	case "$out" in
	*"1 matches, 1 files"*) echo PASS > "$td/result" ;;
	*) echo "FAIL: out=[$out]" > "$td/result" ;;
	esac
}

t_grep_interactive_regex_empty_lines() {
	td=$1
	mkdir -p "$td/sub"
	printf 'foo\n\nbar\n' > "$td/sub/f"
	pdrive --phase 0d --tail '' -- '.' x -R --grep -r "$td/sub"
	out=$(strip_ansi < "$td/out")
	if printf '%s\n' "$out" | grep -qF '[INSERT]' && \
	   printf '%s\n' "$out" | grep -qF '2 matches, 1 files'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: out=[$out]" > "$td/result"
	fi
}

# Regression: grep output should highlight the matched string in red.
# The non-interactive path wraps only the match in \x1b[31m...\x1b[0m.
t_grep_match_highlight() {
	td=$1
	printf 'hello world\nfoo bar\nhello again\n' > "$td/f"
	raw=$("$PROG" hello X --grep "$td/f" 2>/dev/null)
	# Each line should have red around "hello" specifically:
	#   ...31mhello...0m...
	if printf '%s\n' "$raw" | grep -qP '\x1b\[31mhello\x1b\[0m'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: raw=[$(printf '%s' "$raw" | cat -v)]" > "$td/result"
	fi
}

# Regression: grep regex match highlight should cover only the regex match.
t_grep_regex_highlight() {
	td=$1
	printf 'hello world\nfoo bar\nhello again\n' > "$td/f"
	raw=$("$PROG" 'hel+' X -E --grep "$td/f" 2>/dev/null)
	# "hel+" matches "hell" (4 chars), not "hello" (5 chars)
	if printf '%s\n' "$raw" | grep -qP '\x1b\[31mhell\x1b\[0m'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: raw=[$(printf '%s' "$raw" | cat -v)]" > "$td/result"
	fi
}

# Regression: grep_rescan never recompiled the twoway searcher when the find
# string changed in the TUI.  Typing enough chars to cross the twoway
# threshold (>2 chars) caused a segfault from stale shift tables.
t_grep_interactive_edit_during_scan() {
	td=$1; mkdir -p "$td/sub"
	for i in 1 2 3 4; do yes 'hit hix' | head -c 200000 > "$td/sub/f$i"; done
	pdrive --phase 15 --phase 68@50 --phase 69@50 --phase 78@50 \
	       --phase 0d@400 --tail '' -- hit x --grep -r "$td/sub"
	rc=$(cat "$td/rc" 2>/dev/null)
	case "$rc" in
	0|1) echo PASS > "$td/result" ;;
	*) echo "FAIL: rc=$rc" > "$td/result" ;;
	esac
}

t_grep_interactive_stop_during_scan() {
	td=$1; mkdir -p "$td/sub"
	for i in 1 2 3 4; do yes 'hit hix' | head -c 200000 > "$td/sub/f$i"; done
	pdrive --timeout 5 --phase 04 --tail '' -- hit x --grep -r "$td/sub"
	rc=$(cat "$td/rc" 2>/dev/null)
	case "$rc" in
	0|1) echo PASS > "$td/result" ;;
	*) echo "FAIL: rc=$rc" > "$td/result" ;;
	esac
}

t_grep_interactive_rescan_recompile() {
	td=$1
	printf 'there is no point\nfoo bar\n' > "$td/f"
	# Start with find='t', type 'here is no point' (hex) to make it
	# 'there is no point', then Ctrl-D to exit.  Before the fix the
	# child dies from SIGSEGV.
	# 68657265206973206e6f20706f696e74 = 'here is no point'
	# 04 = Ctrl-D
pdrive --phase 68657265206973206e6f20706f696e74 --phase 04 --tail '' -- t x --grep "$td/f"
	rc=$(cat "$td/rc")
	case "$rc" in
		sig:*)
			echo "FAIL: child crashed ($rc)" > "$td/result" ;;
		*)
			echo PASS > "$td/result" ;;
	esac
}

t_grep_interactive_exit_code_match() {
	td=$1
	printf 'hello\nworld\n' > "$td/f"
	# Enter accepts the selected match; the process must exit 0 when a match
	# was found, just like non-interactive --grep.  Previously the tty collect
	# path never set G.grep_matched, so main returned EXIT_FAILURE (1).
	pdrive --phase 0d --tail '' -- hello x --grep "$td/f"
	rc=$(cat "$td/rc" 2>/dev/null)
	out=$(strip_ansi < "$td/out")
	if [ "$rc" = "0" ] && printf '%s\n' "$out" | grep -qF '1:hello'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc out=[$out]" > "$td/result"
	fi
}

t_grep_interactive_enter_during_scan() {
	td=$1
	mkdir -p "$td/dir"
	# Large enough that the live scan is still running when Enter arrives.
	i=1
	while [ "$i" -le 8 ]; do
		awk 'BEGIN { for (j = 1; j <= 100000; j++) print "hit line " j }' > "$td/dir/f$i"
		i=$((i + 1))
	done
	# Enter must select the highlighted match and emit it to stdout immediately.
	# Ctrl-D 50 ms later makes the old deferred-Enter path fail: it quit before
	# the scan END could flush the pending Enter.
	pdrive --ready '-- [INSERT] --' --phase 0d@0 --phase 04@50 --tail '' -- hit x --grep -r "$td/dir"
	rc=$(cat "$td/rc" 2>/dev/null)
	out=$(sed -n '/\x1b\[?1049l/,$p' "$td/out" | strip_ansi)
	if [ "$rc" = "0" ] && printf '%s\n' "$out" | grep -qE ':[0-9]+:hit line'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc out=[$out]" > "$td/result"
	fi
}

t_grep_c_conflict_before_tui() {
	td=$1
	printf 'hello\n' > "$td/f"
	# --grep cannot be combined with -c.  The conflict must be rejected as
	# soon as the flags are parsed, before any target is processed or the
	# interactive TUI is opened and Enter emits a misleading selected line.
	pdrive --noready --timeout 3 -- hello x --grep -c -r "$td/f"
	rc=$(cat "$td/rc" 2>/dev/null)
	if [ "$rc" = "2" ] &&
	   grep -qF 'cannot be combined' "$td/out" &&
	   ! grep -qF "$(printf '\033[?1049h')" "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc" > "$td/result"
	fi
}

TESTS="
t_grep_stdin
t_grep_no_match
t_grep_exit_2_bad_regex
t_grep_conflict_i
t_grep_conflict_c
t_grep_single_file_prefix
t_grep_multiple_files
t_grep_recursive
t_grep_regex_anchor
t_grep_fixed
t_grep_empty_find
t_grep_empty_find_dash
t_grep_empty_find_file
t_grep_empty_input
t_grep_quiet
t_grep_binary
t_grep_dash_stdin_placeholder
t_grep_exclude_cli
t_grep_nonexistent_file
t_grep_interactive_invalid_find
t_grep_interactive_invalid_include
t_grep_interactive_invalid_exclude
t_grep_interactive_regex
t_grep_regex_empty_lines
t_grep_regex_empty_line_anchor
t_grep_files_field_rescan
t_grep_interactive_regex_empty_lines
t_grep_interactive_recursive
t_grep_interactive_basic
t_grep_interactive_scroll
t_grep_interactive_deep_scroll_overdraw
t_grep_interactive_ctrl_j_k_nav
t_grep_interactive_exclude
t_grep_interactive_ctrl_d
t_grep_interactive_multiline
t_grep_interactive_file_cache
t_grep_interactive_find_field
t_grep_interactive_controls_fixed
t_grep_interactive_vim_mode
t_grep_interactive_large_batch
t_grep_interactive_no_blank_while_typing
t_grep_interactive_edit_during_scan
t_grep_interactive_stop_during_scan
t_grep_interactive_rescan_recompile
t_grep_interactive_exit_code_match
t_grep_interactive_enter_during_scan
t_grep_c_conflict_before_tui
t_grep_interactive_blank_after_debounce
t_grep_match_highlight
t_grep_regex_highlight
"
run_suite "grep mode" "$TESTS"
