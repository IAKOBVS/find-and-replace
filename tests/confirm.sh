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
	if echo "$out" | grep -q -- '--- Controls' && echo "$out" | grep -q 'Find:    hello' && echo "$out" | grep -q 'Replace: replacement'; then
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
    # 1. Tab to Flags (\t\t), clear (\x15), set to gR
    # 2. Tab back to Find (5 tabs), clear (\x15), type invalid regex "["
    # 3. Tab to Replace (\t), type "abc"
    # 4. Abort with Ctrl-C (\x03) so we can inspect output
    os.write(fd, b"\t\t\x15gR\t\t\t\t\t\x15[\tabc\x03")
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
	if printf '%s\n' "$clean_tui" | grep -q ':-   hello world' && ! printf '%s\n' "$clean_tui" | grep -q ':\t'; then
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
	cat > "$td/test_vim.py" << 'EOF'
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "replacement", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\x1b")
    time.sleep(0.2)
    os.write(fd, b"0")
    time.sleep(0.1)
    os.write(fd, b"x")
    time.sleep(0.1)
    os.write(fd, b"$")
    time.sleep(0.1)
    os.write(fd, b"i")
    time.sleep(0.1)
    os.write(fd, b"X")
    time.sleep(0.1)
    os.write(fd, b"\x1b")
    time.sleep(0.2)
    os.write(fd, b"j")
    time.sleep(0.1)
    os.write(fd, b"0")
    time.sleep(0.1)
    os.write(fd, b"x")
    time.sleep(0.1)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
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
	out=$(python3 "$td/test_vim.py" "$td" 2>/dev/null)
	if [ "$(cat "$td/f")" = 'hello world' ] && echo "$out" | grep -q -- '--- Controls \[NORMAL\] ---'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim motions check failed. f=[$(cat "$td/f")] out=[$out]" > "$td/result"
	fi
}

t_confirm_vim_word_motions() {
	td=$1; printf 'hello world\n' > "$td/f"
	cat > "$td/test_vim_word.py" << 'EOF'
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "foo-bar baz", "replacement", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\x1b")
    time.sleep(0.2)
    os.write(fd, b"0")
    time.sleep(0.1)
    os.write(fd, b"w")
    time.sleep(0.1)
    os.write(fd, b"x")
    time.sleep(0.1)
    os.write(fd, b"b")
    time.sleep(0.1)
    os.write(fd, b"x")
    time.sleep(0.1)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
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
	out=$(python3 "$td/test_vim_word.py" "$td" 2>/dev/null)
	if echo "$out" | grep -q 'Find:    oobar baz'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim word motions check failed. out=[$out]" > "$td/result"
	fi
}

t_confirm_vim_delete_eol() {
	td=$1; printf 'hell world\n' > "$td/f"
	cat > "$td/test_vim_del_eol.py" << 'EOF'
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "replacement", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\x1b")
    time.sleep(0.2)
    os.write(fd, b"x")
    time.sleep(0.2)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
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
	out=$(python3 "$td/test_vim_del_eol.py" "$td" 2>/dev/null)
	if echo "$out" | grep -q 'Find:    hell'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim delete eol check failed. out=[$out]" > "$td/result"
	fi
}

t_confirm_vim_delete_dd() {
	td=$1; printf 'hello world\n' > "$td/f"
	cat > "$td/test_vim_dd.py" << 'EOF'
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "replacement", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\x1b")
    time.sleep(0.2)
    os.write(fd, b"dd")
    time.sleep(0.2)
    os.write(fd, b"ihello")
    time.sleep(0.2)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
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
	out=$(python3 "$td/test_vim_dd.py" "$td" 2>/dev/null)
	if echo "$out" | grep -q 'Find:    hello' && [ "$(cat "$td/f")" = 'replacement world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim dd check failed. out=[$out]" > "$td/result"
	fi
}

t_confirm_vim_change_cw() {
	td=$1; printf 'qux-bar world\n' > "$td/f"
	cat > "$td/test_vim_cw.py" << 'EOF'
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "foo-bar", "replacement", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\x1b")
    time.sleep(0.2)
    os.write(fd, b"0")
    time.sleep(0.1)
    os.write(fd, b"cwqux")
    time.sleep(0.2)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
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
	out=$(python3 "$td/test_vim_cw.py" "$td" 2>/dev/null)
	if echo "$out" | grep -q 'Find:    qux-bar' && [ "$(cat "$td/f")" = 'replacement world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: vim cw check failed. out=[$out]" > "$td/result"
	fi
}

t_confirm_interactive_include_exclude() {
	td=$1; mkdir -p "$td/d"
	printf 'hello\n' > "$td/d/a.txt"; printf 'hello\n' > "$td/d/b.txt"; printf 'hello\n' > "$td/d/c.c"
	python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "HI", "-c", "-i", "-r", os.path.join(sys.argv[1], "d")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    # 4 tabs to Include, clear, set to "\\.txt$"; tab to Exclude, clear, set to "^b"
    os.write(fd, b"\t\t\t\t\x15\\.txt$\t\x15^b")
    time.sleep(0.5)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
' "$td" 2>/dev/null
	ta=$(cat "$td/d/a.txt"); tb=$(cat "$td/d/b.txt"); tc=$(cat "$td/d/c.c")
	[ "$ta" = 'HI' ] && [ "$tb" = 'hello' ] && [ "$tc" = 'hello' ] && echo PASS > "$td/result" || echo "FAIL: a [$ta] b [$tb] c [$tc]" > "$td/result"
}

t_confirm_interactive_backup() {
	td=$1; printf 'hello\n' > "$td/f"
	python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "HI", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    # 6 tabs to Backup, clear, set to "bak"
    os.write(fd, b"\t\t\t\t\t\t\x15bak")
    time.sleep(0.5)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
' "$td" 2>/dev/null
	[ "$(cat "$td/f")" = 'HI' ] && [ "$(cat "$td/fbak")" = 'hello' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")] fbak=[$(cat "$td/fbak" 2>/dev/null)]" > "$td/result"
}

t_confirm_interactive_l_flag() {
	td=$1; printf 'hello\n' > "$td/f"
	out=$(python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "HI", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    # 2 tabs to Flags, clear, set to "l"
    os.write(fd, b"\t\t\x15l")
    time.sleep(0.5)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
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
	[ "$(cat "$td/f")" = 'HI' ] && printf '%s\n' "$out" | grep -q "$td/f" && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")] path-not-printed" > "$td/result"
}

t_confirm_interactive_clear_filters() {
	td=$1; mkdir -p "$td/d"
	printf 'hello\n' > "$td/d/a.txt"; printf 'hello\n' > "$td/d/b.txt"
	python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "HI", "-c", "-i", "-r", os.path.join(sys.argv[1], "d")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    # 4 tabs to Include, type "\\.txt$"; clear it (Ctrl-U); tab to Exclude,
    # type "^b"; clear it (Ctrl-U)
    os.write(fd, b"\t\t\t\t\\.txt$\x15\t^b\x15")
    time.sleep(0.5)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
' "$td" 2>/dev/null
	ta=$(cat "$td/d/a.txt"); tb=$(cat "$td/d/b.txt")
	[ "$ta" = 'HI' ] && [ "$tb" = 'HI' ] && echo PASS > "$td/result" || echo "FAIL: a [$ta] b [$tb]" > "$td/result"
}

t_confirm_interactive_invalid_exclude() {
	td=$1; printf 'hello world\n' > "$td/f"
	out=$(python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "HI", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    # 5 tabs to Exclude, type invalid regex "[", abort
    os.write(fd, b"\t\t\t\t\t[\x03")
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
	if echo "$out" | grep -q 'Invalid Exclude regex'; then
		echo PASS > "$td/result"
	else
		echo "FAIL: invalid exclude regex not reported. out=[$out]" > "$td/result"
	fi
}

t_confirm_interactive_flags_ei() {
	td=$1; printf 'HeLLo world\n' > "$td/f"
	python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "HI", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    # 2 tabs to Flags, clear, set to "EIz" (extended + icase regex, -z)
    os.write(fd, b"\t\t\x15EIz")
    time.sleep(0.5)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
' "$td" 2>/dev/null
	[ "$(cat "$td/f")" = 'HI world' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")]" > "$td/result"
}

t_vim_normal_mode_word_motions() {
	td=$1; printf 'foo bar az\n' > "$td/f"
	rc=$(python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "foo bar baz", "X", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\x1b")
    time.sleep(0.3)
    for k in [b"0", b"w", b"w", b"x", b"b", b"w", b"w"]:
        os.write(fd, k)
        time.sleep(0.1)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
    output = b""
    try:
        while True:
            data = os.read(fd, 1024)
            if not data: break
            output += data
    except OSError:
        pass
    with open(os.path.join(sys.argv[1], "out"), "wb") as fh:
        fh.write(output)
    print(0)
' "$td" 2>/dev/null)
	if [ "$rc" = 0 ] && [ "$(cat "$td/f")" = 'X' ] && grep -q 'Find:    foo bar az' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc f=[$(cat "$td/f")] out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

t_vim_delete_ops() {
	td=$1
	cat > "$td/drive.py" << 'EOF'
import os, pty, sys, time
f, find, rplc, keys, tail = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", find, rplc, "-c", "-i", f], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\x1b")
    time.sleep(0.3)
    for k in keys.split(","):
        os.write(fd, bytes.fromhex(k))
        time.sleep(0.15)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, tail.encode("utf-8").decode("unicode_escape").encode("utf-8"))
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
EOF
	good=1
	# dw: 0 d w -> find "bar baz"
	printf 'foo bar baz\n' > "$td/f1"
	python3 "$td/drive.py" "$td/f1" 'foo bar baz' X '30,64,77' 'y\n' 2>/dev/null
	[ "$(cat "$td/f1")" = 'foo X' ] || good=0
	# db: $ d b -> find "foo bar z" (no match, cursor clamps to end-1)
	printf 'foo bar baz\n' > "$td/f2"
	python3 "$td/drive.py" "$td/f2" 'foo bar baz' X '24,64,62' 'y\n' 2>/dev/null
	[ "$(cat "$td/f2")" = 'foo bar baz' ] || good=0
	# d0: $ d 0 -> find "z"
	printf 'foo bar baz\n' > "$td/f3"
	python3 "$td/drive.py" "$td/f3" 'foo bar baz' X '24,64,30' 'y\n' 2>/dev/null
	[ "$(cat "$td/f3")" = 'foo bar baX' ] || good=0
	# d0: b d 0 -> find "baz"
	printf 'foo bar baz\n' > "$td/f4"
	python3 "$td/drive.py" "$td/f4" 'foo bar baz' X '62,64,30' 'y\n' 2>/dev/null
	[ "$(cat "$td/f4")" = 'foo bar X' ] || good=0
	# d$: 0 d $ -> find empty, no matches, file untouched
	printf 'foo bar baz\n' > "$td/f5"
	python3 "$td/drive.py" "$td/f5" 'foo bar baz' X '30,64,24' 'y\n' 2>/dev/null
	[ "$(cat "$td/f5")" = 'foo bar baz' ] || good=0
	# dd: 0 d d -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f6"
	python3 "$td/drive.py" "$td/f6" 'foo bar baz' X '30,64,64' 'y\n' 2>/dev/null
	[ "$(cat "$td/f6")" = 'foo bar baz' ] || good=0
	# x: 0 x -> delete first char -> find "oo bar baz"
	printf 'foo bar baz\n' > "$td/f7"
	python3 "$td/drive.py" "$td/f7" 'foo bar baz' X '30,78' 'y\n' 2>/dev/null
	[ "$(cat "$td/f7")" = 'fX' ] || good=0
	# X: $ X -> delete char before end cursor -> find "foo bar bz" (no match)
	printf 'foo bar baz\n' > "$td/f8"
	python3 "$td/drive.py" "$td/f8" 'foo bar baz' X '24,58' 'y\n' 2>/dev/null
	[ "$(cat "$td/f8")" = 'foo bar baz' ] || good=0
	# D: 0 D -> delete to end -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f9"
	python3 "$td/drive.py" "$td/f9" 'foo bar baz' X '30,44' 'y\n' 2>/dev/null
	[ "$(cat "$td/f9")" = 'foo bar baz' ] || good=0
	if [ "$good" -eq 1 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")] f3=[$(cat "$td/f3")] f4=[$(cat "$td/f4")] f5=[$(cat "$td/f5")] f6=[$(cat "$td/f6")] f7=[$(cat "$td/f7")] f8=[$(cat "$td/f8")] f9=[$(cat "$td/f9")]" > "$td/result"
	fi
}

t_vim_change_ops() {
	td=$1
	cat > "$td/drive.py" << 'EOF'
import os, pty, sys, time
f, find, rplc, keys, tail = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", find, rplc, "-c", "-i", f], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\x1b")
    time.sleep(0.3)
    for k in keys.split(","):
        os.write(fd, bytes.fromhex(k))
        time.sleep(0.15)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, tail.encode("utf-8").decode("unicode_escape").encode("utf-8"))
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
EOF
	good=1
	# cw: 0 c w -> find "bar baz", insert mode
	printf 'foo bar baz\n' > "$td/f1"
	python3 "$td/drive.py" "$td/f1" 'foo bar baz' X '30,63,77' 'y\n' 2>/dev/null
	[ "$(cat "$td/f1")" = 'foo X' ] || good=0
	# cb: 0 c b -> no-op (cursor at 0), find unchanged
	printf 'foo bar baz\n' > "$td/f2"
	python3 "$td/drive.py" "$td/f2" 'foo bar baz' X '30,63,62' 'y\n' 2>/dev/null
	[ "$(cat "$td/f2")" = 'X' ] || good=0
	# c0: $ c 0 -> find "z"
	printf 'foo bar baz\n' > "$td/f3"
	python3 "$td/drive.py" "$td/f3" 'foo bar baz' X '24,63,30' 'y\n' 2>/dev/null
	[ "$(cat "$td/f3")" = 'foo bar baX' ] || good=0
	# c$: 0 c $ -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f4"
	python3 "$td/drive.py" "$td/f4" 'foo bar baz' X '30,63,24' 'y\n' 2>/dev/null
	[ "$(cat "$td/f4")" = 'foo bar baz' ] || good=0
	# cc: 0 c c -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f5"
	python3 "$td/drive.py" "$td/f5" 'foo bar baz' X '30,63,63' 'y\n' 2>/dev/null
	[ "$(cat "$td/f5")" = 'foo bar baz' ] || good=0
	# C: 0 w C -> find "foo ", file "Xbar baz"
	printf 'foo bar baz\n' > "$td/f6"
	python3 "$td/drive.py" "$td/f6" 'foo bar baz' X '30,77,43' 'y\n' 2>/dev/null
	[ "$(cat "$td/f6")" = 'Xbar baz' ] || good=0
	# C: 0 C -> find empty, file untouched
	printf 'foo bar baz\n' > "$td/f7"
	python3 "$td/drive.py" "$td/f7" 'foo bar baz' X '30,43' 'y\n' 2>/dev/null
	[ "$(cat "$td/f7")" = 'foo bar baz' ] || good=0
	if [ "$good" -eq 1 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")] f3=[$(cat "$td/f3")] f4=[$(cat "$td/f4")] f5=[$(cat "$td/f5")] f6=[$(cat "$td/f6")] f7=[$(cat "$td/f7")]" > "$td/result"
	fi
}

t_vim_insert_motions() {
	td=$1
	cat > "$td/drive.py" << 'EOF'
import os, pty, sys, time
f, find, rplc, keys, tail = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", find, rplc, "-c", "-i", f], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\x1b")
    time.sleep(0.3)
    for k in keys.split(","):
        os.write(fd, bytes.fromhex(k))
        time.sleep(0.15)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, tail.encode("utf-8").decode("unicode_escape").encode("utf-8"))
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
EOF
	good=1
	# I: insert at home -> find "Xhello"
	printf 'Xhello world\n' > "$td/f1"
	python3 "$td/drive.py" "$td/f1" hello R '49,58' 'y\n' 2>/dev/null
	[ "$(cat "$td/f1")" = 'R world' ] || good=0
	# A: insert at end -> find "helloX"
	printf 'helloX world\n' > "$td/f2"
	python3 "$td/drive.py" "$td/f2" hello R '41,58' 'y\n' 2>/dev/null
	[ "$(cat "$td/f2")" = 'R world' ] || good=0
	# 0 l i: insert at cursor 1 -> find "hXello"
	printf 'hXello world\n' > "$td/f3"
	python3 "$td/drive.py" "$td/f3" hello R '30,6c,69,58' 'y\n' 2>/dev/null
	[ "$(cat "$td/f3")" = 'R world' ] || good=0
	# 0 l a: append after cursor -> find "heXllo"
	printf 'heXllo world\n' > "$td/f4"
	python3 "$td/drive.py" "$td/f4" hello R '30,6c,61,58' 'y\n' 2>/dev/null
	[ "$(cat "$td/f4")" = 'R world' ] || good=0
	if [ "$good" -eq 1 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")] f3=[$(cat "$td/f3")] f4=[$(cat "$td/f4")]" > "$td/result"
	fi
}

t_vim_jk_field_nav() {
	td=$1
	cat > "$td/drive.py" << 'EOF'
import os, pty, sys, time
f, find, rplc, keys, tail = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", find, rplc, "-c", "-i", f], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\x1b")
    time.sleep(0.3)
    for k in keys.split(","):
        os.write(fd, bytes.fromhex(k))
        time.sleep(0.15)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, tail.encode("utf-8").decode("unicode_escape").encode("utf-8"))
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
EOF
	good=1
	# j: down to Replace, i inserts at cursor (clamped to end-1), type zz
	printf 'hello world\n' > "$td/f1"
	python3 "$td/drive.py" "$td/f1" hello replacement '6a,69,7a,7a' 'y\n' 2>/dev/null
	[ "$(cat "$td/f1")" = 'replacemenzzt world' ] || good=0
	# k k j: up to Backup (wrap), down to Exclude... then j to Backup, type bak suffix
	printf 'hello world\n' > "$td/f2"
	python3 "$td/drive.py" "$td/f2" hello replacement '6b,6b,6a,69,62616b' 'y\n' 2>/dev/null
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
	rc=$(python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "X", "Y", "-c", "-i", "-g", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib", "LINES": ""})
else:
    time.sleep(0.5)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
    output = b""
    try:
        while True:
            data = os.read(fd, 1024)
            if not data: break
            output += data
    except OSError:
        pass
    with open(os.path.join(sys.argv[1], "out"), "wb") as fh:
        fh.write(output)
    print(0)
' "$td" 2>/dev/null)
	yg=$(tr -cd 'Y' < "$td/f" | wc -c)
	if [ "$rc" = 0 ] && [ "$yg" -eq 20 ] && grep -q '20 matches, 1 files' "$td/out" && grep -q 'some previews omitted' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc yg=$yg out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

t_terminal_cols_env() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=$(python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "HI", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib", "COLUMNS": "30"})
else:
    time.sleep(0.5)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
    output = b""
    try:
        while True:
            data = os.read(fd, 1024)
            if not data: break
            output += data
    except OSError:
        pass
    with open(os.path.join(sys.argv[1], "out"), "wb") as fh:
        fh.write(output)
    print(0)
' "$td" 2>/dev/null)
	if [ "$rc" = 0 ] && [ "$(cat "$td/f")" = 'HI world' ] && grep -q '1 matches, 1 files' "$td/out" && grep -q 'Find:    hello' "$td/out"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc f=[$(cat "$td/f")] out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

t_interactive_signal_term() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=$(python3 -c '
import os, pty, sys, time, signal
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "HI", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.kill(pid, signal.SIGTERM)
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        print(os.WEXITSTATUS(status))
    else:
        print(-os.WTERMSIG(status))
' "$td" 2>/dev/null)
	if [ "$rc" = 1 ] && [ "$(cat "$td/f")" = 'hello world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc file=[$(cat "$td/f")]" > "$td/result"
	fi
}

t_interactive_file_deleted_rename_fail() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=$(python3 -c '
import os, pty, sys, time
f = os.path.join(sys.argv[1], "f")
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "bye", "-c", "-i", f], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.unlink(f)
    os.mkdir(f)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
    output = b""
    try:
        while True:
            data = os.read(fd, 1024)
            if not data: break
            output += data
    except OSError:
        pass
    _, status = os.waitpid(pid, 0)
    code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
    print(code, b"rename temp file" in output)
' "$td" 2>/dev/null)
	[ "$rc" = '1 True' ] && echo PASS > "$td/result" || echo "FAIL: rc=[$rc]" > "$td/result"
}

t_interactive_invalid_flag_char() {
	td=$1; printf 'hello world\n' > "$td/f"
	rc=$(python3 -c '
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "HI", "-c", "-i", os.path.join(sys.argv[1], "f")], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    # 2 tabs to Flags, clear, type invalid flag char "x"
    os.write(fd, b"\t\t\x15x")
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
    with open(os.path.join(sys.argv[1], "out"), "wb") as fh:
        fh.write(output)
    _, status = os.waitpid(pid, 0)
    print(os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1)
' "$td" 2>/dev/null)
	if [ "$rc" = 1 ] && grep -q 'Flags:   x' "$td/out" && [ "$(cat "$td/f")" = 'hello world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: rc=$rc out=[$(sed 's/\x1b\[[0-9;]*m//g' "$td/out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)]" > "$td/result"
	fi
}

t_interactive_arrows() {
	td=$1
	cat > "$td/drive.py" << 'EOF'
import os, pty, sys, time
f, find, rplc, keys, tail = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", find, rplc, "-c", "-i", f], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    for k in keys.split(","):
        os.write(fd, bytes.fromhex(k))
        time.sleep(0.25)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, tail.encode("utf-8").decode("unicode_escape").encode("utf-8"))
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
EOF
	good=1
	# up, down, right, left, right (restore cursor), shift-tab, delete, shift-tab,
	# down, down (back to Find), type X -> find "helloX"
	printf 'helloX world\n' > "$td/f1"
	python3 "$td/drive.py" "$td/f1" hello replacement '1b5b41,1b5b42,1b5b43,1b5b44,1b5b43,1b5b5a,1b5b337e,1b5b5a,1b5b42,1b5b42,58' 'y\n' 2>/dev/null
	[ "$(cat "$td/f1")" = 'replacement world' ] || good=0
	# ESC 0 then Delete key in normal mode deletes first char -> find "ello"
	printf 'hello world\n' > "$td/f2"
	python3 "$td/drive.py" "$td/f2" hello replacement '1b,30,1b5b337e' 'y\n' 2>/dev/null
	[ "$(cat "$td/f2")" = 'hreplacement world' ] || good=0
	if [ "$good" -eq 1 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: f1=[$(cat "$td/f1")] f2=[$(cat "$td/f2")]" > "$td/result"
	fi
}

t_interactive_ctrl_j_k() {
	td=$1; printf 'hello world\n' > "$td/f"
	cat > "$td/drive.py" << 'EOF'
import os, pty, sys, time
f, find, rplc, keys, tail = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", find, rplc, "-c", "-i", f], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    for k in keys.split(","):
        os.write(fd, bytes.fromhex(k))
        time.sleep(0.25)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, tail.encode("utf-8").decode("unicode_escape").encode("utf-8"))
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
EOF
	# Ctrl-J down (Replace), Ctrl-J down (Flags), Ctrl-K up (Replace), type zz
	python3 "$td/drive.py" "$td/f" hello replacement '0a,0a,0b,7a,7a' 'y\n' 2>/dev/null
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
	cat > "$td/drive.py" << 'EOF'
import os, pty, sys, time
f, find, rplc, keys, tail = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", find, rplc, "-c", "-i", f], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    os.write(fd, b"\x1b")
    time.sleep(0.3)
    for k in keys.split(","):
        os.write(fd, bytes.fromhex(k))
        time.sleep(0.15)
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, tail.encode("utf-8").decode("unicode_escape").encode("utf-8"))
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
EOF
	# dd empties the find field; no matches -> no prompt, file untouched
	python3 "$td/drive.py" "$td/f" 'foo bar' X '64,64' 'n\n' 2>/dev/null
	[ "$(cat "$td/f")" = 'foo bar baz' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")]" > "$td/result"
}

t_confirm_abstractions() {
	td=$1; printf 'hello abstractions\n' > "$td/f"
	cat > "$td/drive.py" << 'EOF'
import os, pty, sys, time
f = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("./find-and-replace", ["./find-and-replace", "hello", "world", "-c", "-i", f], {"LD_LIBRARY_PATH": "lib/jstring/build/lib"})
else:
    time.sleep(0.5)
    # 1. Down to Replace (Ctrl-J: \x0a)
    os.write(fd, b"\x0a")
    time.sleep(0.1)
    # 2. Append "!!" to Replace
    os.write(fd, b"!!")
    time.sleep(0.1)
    # 3. Up to Find (Ctrl-K: \x0b)
    os.write(fd, b"\x0b")
    time.sleep(0.1)
    # 4. Accept with Enter (\r), then confirm with 'y'
    os.write(fd, b"\r")
    time.sleep(0.5)
    os.write(fd, b"y\n")
    try:
        while True:
            if not os.read(fd, 1024): break
    except OSError:
        pass
EOF
	python3 "$td/drive.py" "$td/f" 2>/dev/null
	[ "$(cat "$td/f")" = 'world!! abstractions' ] && echo PASS > "$td/result" || echo "FAIL: f=[$(cat "$td/f")]" > "$td/result"
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
"

run_suite "confirm tests" "$TESTS"
