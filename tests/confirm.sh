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
	[ "$(cat "$td/f")" = 'hi' ] && printf '%s' "$clean_out" | grep -q -- ':-1:hello' && printf '%s' "$clean_out" | grep -q -- ':+1:hi' && ! printf '%s' "$clean_out" | grep -q '^@@' && ! printf '%s' "$clean_out" | grep -q '^---' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$out]" > "$td/result"
}

t_confirm_multi_same_line() {
	td=$1; printf 'la la\nla la\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" la lu -c -i -g "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'lu lu
lu lu' ] && [ "$(printf '%s\n' "$clean_out" | grep -c -- ':-0:la la')" -eq 2 ] && [ "$(printf '%s\n' "$clean_out" | grep -c -- ':+0:lu lu')" -eq 2 ] && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$out]" > "$td/result"
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
	[ "$(cat "$td/f")" = "$expected_file" ] && printf '%s' "$clean_out" | grep -q -- ':-0:hello' && printf '%s' "$clean_out" | grep -q -- ':+0:world' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_regex_preview_skip_newline() {
	td=$1; printf ' b\n b\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" ".* b" "b" -gc -i -RE "$td/f" 2>/dev/null)
	clean_out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	# Under latest jstring, ".* b" replaced with "b" (with REG_NEWLINE) produces "b\nb\n"
	[ "$(cat "$td/f")" = 'b
b' ] && printf '%s' "$clean_out" | grep -q -- ':-0: b' && printf '%s' "$clean_out" | grep -q -- ':+0:b' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_regex_preview_backref() {
	td=$1; printf 'hello\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" "(h)ello" '\\1world' -gc -i -E "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(cat "$td/f")" = 'hworld' ] && printf '%s\n' "$clean_out" | grep -q -- ':-0:hello' && printf '%s\n' "$clean_out" | grep -q -- ':+0:hworld' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_preview_line_numbers_shift() {
	td=$1; printf 'a\nhello\nc\nhello\nd\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" hello 'one\ntwo' -c -i -g "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	good=1
	for want in ':2:-1:hello' ':2:+1:one' ':3:+1:two' ':4:-1:hello' ':5:+1:one' ':6:+1:two'; do
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
	[ "$(cat "$td/f")" = 'yes newline' ] && printf '%s\n' "$clean_out" | grep -q -- ':1:-0:no newline' && printf '%s\n' "$clean_out" | grep -q -- ':1:+0:yes newline' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_preview_delete_line() {
	td=$1; printf 'DELETE\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" DELETE '' -c -i "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	[ "$(wc -c < "$td/f")" -eq 1 ] && printf '%s\n' "$clean_out" | grep -q -- ':1:-0:DELETE' && printf '%s\n' "$clean_out" | grep -q -- ':1:+0:$' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
}

t_confirm_preview_empty_line_insert() {
	td=$1; printf 'a\n\nb\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" '^$' X -gc -i -R "$td/f" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	exp='a
X
b'
	[ "$(cat "$td/f")" = "$exp" ] && printf '%s\n' "$clean_out" | grep -q -- ':2:-0:$' && printf '%s\n' "$clean_out" | grep -q -- ':2:+0:X' && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")] out=[$clean_out]" > "$td/result"
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
	n=$(printf '%s\n' "$clean_out" | grep -c -- ':-0:X$')
	yg=$(tr -cd 'Y' < "$td/f" | wc -c)
	xg=$(tr -cd 'X' < "$td/f" | wc -c)
	[ "$n" -eq 50 ] && [ "$yg" -eq 50 ] && [ "$xg" -eq 0 ] && printf '%s\n' "$clean_out" | grep -q -- ':100:-0:X' && printf '%s\n' "$clean_out" | grep -q -- ':5000:-0:X' && printf '%s\n' "$clean_out" | grep -q -- ':5000:+0:Y' && echo PASS > "$td/result" || echo "FAIL: n=$n yg=$yg xg=$xg out=[$(printf '%s\n' "$clean_out" | head -3)]" > "$td/result"
}

t_confirm_interactive_live_preview() {
	td=$1; printf 'hello world\n' > "$td/f"
	python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "replacement", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\x7f\x7f\x7f\x7f\x7fworld\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
' "$td" 2>/dev/null
	[ "$(cat "$td/f")" = 'hello replacement' ] && echo PASS > "$td/result" || echo "FAIL: file=[$(cat "$td/f")]" > "$td/result"
}

t_confirm_interactive_multi_field() {
	td=$1; printf 'hello world\n' > "$td/f1"; printf 'hello again\n' > "$td/f2"
	python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "replacement", "-c", "-i", os.path.join(sys.argv[1], "f1"), os.path.join(sys.argv[1], "f2")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\t\x15newreplace\t\x15gR\tf2\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
' "$td" 2>/dev/null
	[ "$(cat "$td/f1")" = 'hello world' ] && [ "$(cat "$td/f2")" = 'newreplace again' ] && echo PASS > "$td/result" || echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")]" > "$td/result"
}

t_confirm_interactive_layout() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$(python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "replacement", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"n\n")
    output = b""
    try:
        while True:
            data = os.read(fd, 1024)
            if not data: break
            output += data
    except OSError:
        pass
    print(output.decode("utf-8", errors="ignore"))
' "$td" 2>/dev/null)
	if echo "$out" | grep -q -- '--- Controls ---' && echo "$out" | grep -q 'Find:    hello' && echo "$out" | grep -q 'Replace: replacement'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: layout check failed. out=[$out]" > "$td/result"
	fi
}

t_confirm_interactive_error_preview() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$(python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "replacement", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    # 1. Tab to Flags (\t), clear (\x15), set to gR
    # 2. Tab to Find (\t\t), clear (\x15), type invalid regex "["
    # 3. Tab to Replace (\t), type "abc"
    # 4. Abort with Ctrl-C (\x03) so we can inspect output
    os.write(fd, b"\t\t\x15gR\t\t\x15[\tabc\x03")
    output = b""
    try:
        while True:
            data = os.read(fd, 1024)
            if not data: break
            output += data
    except OSError:
        pass
    print(output.decode("utf-8", errors="ignore"))
' "$td" 2>/dev/null)
	# Check that the "Regex error:" string appears in the final frame where Replace contains "replacementabc"
	if echo "$out" | grep -q 'Regex error:' && echo "$out" | grep -q 'Replace: replacementabc'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: error preview check failed. out=[$out]" > "$td/result"
	fi
}

t_confirm_interactive_backref_mismatch() {
	td=$1; printf 'hello world\n' > "$td/f"
	cat > "$td/test.py" << 'EOF'
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "\\\\\\\\1\\\\\\\\2", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    # 1. Tab to Flags (\t), clear (\x15), set to gR
    os.write(fd, b"\t\t\x15gR")
    time.sleep(1.5)
    # 2. Abort with Ctrl-C (\x03)
    os.write(fd, b"\x03")
    output = b""
    try:
        while True:
            data = os.read(fd, 1024)
            if not data: break
            output += data
    except OSError:
        pass
    print(output.decode("utf-8", errors="ignore"))
EOF
	out=$(python3 "$td/test.py" "$td" 2>/dev/null)
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
	out=$(python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "replacement", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"n\n")
    output = b""
    try:
        while True:
            data = os.read(fd, 1024)
            if not data: break
            output += data
    except OSError:
        pass
    print(output.decode("utf-8", errors="ignore"))
' "$td" 2>/dev/null)
	if echo "$out" | grep -q '1 matches, 1 files'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: stats not found. out=[$out]" > "$td/result"
	fi
}

t_confirm_interactive_height_capping() {
	td=$1; printf 'line 1\nline 2\nline 3\nline 4\nline 5\n' > "$td/f"
	out=$(python3 -c '
import os, pty, sys, time, fcntl, termios, struct
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "line", "replacement", "-c", "-i", "-g", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    # Set size to 12 rows, 80 cols
    s = struct.pack("HHHH", 12, 80, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, s)
    time.sleep(0.5)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"n\n")
    output = b""
    try:
        while True:
            data = os.read(fd, 1024)
            if not data: break
            output += data
    except OSError:
        pass
    print(output.decode("utf-8", errors="ignore"))
' "$td" 2>/dev/null)
	clean_out=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
	# Count only the printed preview lines in raw interactive mode (marked by \x1b[K / [K)
	lines_count=$(printf '%s\n' "$out" | grep '_interactive_height_capping/f' | grep -c '\[K')
	if printf '%s\n' "$clean_out" | grep -q 'some previews omitted' && [ "$lines_count" -le 3 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: height capping failed. lines=$lines_count out=[$clean_out]" > "$td/result"
	fi
}

t_confirm_interactive_tab_expansion() {
	td=$1; printf '\thello world\n' > "$td/f"
	out=$(python3 -c '
import os, pty, sys, time, fcntl, termios, struct
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "replacement", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    s = struct.pack("HHHH", 24, 80, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, s)
    time.sleep(0.5)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"n\n")
    output = b""
    try:
        while True:
            data = os.read(fd, 1024)
            if not data: break
            output += data
    except OSError:
        pass
    print(output.decode("utf-8", errors="ignore"))
' "$td" 2>/dev/null)
	tui_out=$(printf '%s\n' "$out" | grep '\[K')
	clean_tui=$(printf '%s\n' "$tui_out" | sed 's/\x1b\[[0-9;]*m//g; s/\x1b\[K//g; s/\[K//g')
	if printf '%s\n' "$clean_tui" | grep -q ':-0: hello world' && ! printf '%s\n' "$clean_tui" | grep -q ':\t'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: tab expansion failed. tui=[$clean_tui]" > "$td/result"
	fi
}

t_confirm_interactive_width_clipping() {
	td=$1
	python3 -c 'import sys; print("a" * 150)' > "$td/f"
	out=$(python3 -c '
import os, pty, sys, time, fcntl, termios, struct
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "a", "b", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    s = struct.pack("HHHH", 24, 80, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, s)
    time.sleep(0.5)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"n\n")
    output = b""
    try:
        while True:
            data = os.read(fd, 1024)
            if not data: break
            output += data
    except OSError:
        pass
    print(output.decode("utf-8", errors="ignore"))
' "$td" 2>/dev/null)
	tui_out=$(printf '%s\n' "$out" | grep '_interactive_width_clipping/f' | grep '\[K' | head -1)
	clean_line=$(printf '%s\n' "$tui_out" | sed -E 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\r//g')
	if [ -n "$clean_line" ] && [ "${#clean_line}" -le 79 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: width clipping failed. line_len=${#clean_line} line=[$clean_line]" > "$td/result"
	fi
}

t_confirm_preview_new_format() {
	td=$1; printf 'hello\n' > "$td/f"
	out=$(printf 'y\n' | "$PROG" hello world -c -i "$td/f" 2>/dev/null)
	expected_old=$(printf '\033[31m%s\033[0m:\033[32m1\033[0m:\033[31m-0\033[0m:\033[31mhello' "$td/f")
	expected_new=$(printf '\033[31m%s\033[0m:\033[32m1\033[0m:\033[32m+0\033[0m:\033[32mworld' "$td/f")
	if printf '%s\n' "$out" | grep -F -q "$expected_old" && printf '%s\n' "$out" | grep -F -q "$expected_new"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: new format test failed. out=[$out]" > "$td/result"
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
t_confirm_preview_new_format
"
run_suite "confirm tests" "$TESTS"
