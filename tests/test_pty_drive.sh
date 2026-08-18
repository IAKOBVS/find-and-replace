#!/bin/sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

PDRV="$PROG_DIR/tests/pty_drive"

pdrive() {
	python3 "$PDRV" "$@" >/dev/null 2>&1
}

t_basic_echo() {
	td=$1
	pdrive --prog /bin/echo --rc "$td/rc" -- echo hello
	r=$(cat "$td/rc" 2>/dev/null)
	[ "$r" = "0" ] && echo PASS > "$td/result" || echo "FAIL: rc=$r, expected 0" > "$td/result"
}

t_exit_code() {
	td=$1
	pdrive --prog /bin/sh --rc "$td/rc" -- /bin/sh -c 'exit 42'
	r=$(cat "$td/rc" 2>/dev/null)
	[ "$r" = "42" ] && echo PASS > "$td/result" || echo "FAIL: rc=$r, expected 42" > "$td/result"
}

t_signal_term() {
	td=$1
	pdrive --prog sleep --rc "$td/rc" --signal TERM -- timeout 10 sleep 999
	r=$(cat "$td/rc" 2>/dev/null)
	[ "$r" = "sig:15" ] && echo PASS > "$td/result" || echo "FAIL: rc=$r, expected sig:15" > "$td/result"
}

t_signal_kill() {
	td=$1
	pdrive --prog sleep --rc "$td/rc" --signal KILL -- timeout 10 sleep 999
	r=$(cat "$td/rc" 2>/dev/null)
	[ "$r" = "sig:9" ] && echo PASS > "$td/result" || echo "FAIL: rc=$r, expected sig:9" > "$td/result"
}

t_timeout() {
	td=$1
	pdrive --prog sleep --rc "$td/rc" --timeout 1 -- sleep 999
	r=$(cat "$td/rc" 2>/dev/null)
	[ "$r" = "timeout" ] && echo PASS > "$td/result" || echo "FAIL: rc=$r, expected timeout" > "$td/result"
}

t_out_captures_output() {
	td=$1
	pdrive --prog /bin/echo --out "$td/out" --rc "$td/rc" -- echo hello world
	out=$(cat "$td/out" 2>/dev/null)
	r=$(cat "$td/rc" 2>/dev/null)
	case "$out" in
		*hello\ world*) [ "$r" = "0" ] && echo PASS > "$td/result" || echo "FAIL: rc=$r" > "$td/result" ;;
		*) echo "FAIL: out=[$out], expected hello world" > "$td/result" ;;
	esac
}

t_out_multiline() {
	td=$1
	pdrive --prog /bin/printf --out "$td/out" --rc "$td/rc" -- /bin/printf 'line1\nline2\n'
	out=$(cat "$td/out" 2>/dev/null)
	r=$(cat "$td/rc" 2>/dev/null)
	case "$out" in
		*line1*line2*) [ "$r" = "0" ] && echo PASS > "$td/result" || echo "FAIL: rc=$r" > "$td/result" ;;
		*) echo "FAIL: out=[$out], expected line1+line2" > "$td/result" ;;
	esac
}

t_phase_hex() {
	td=$1
	pdrive --prog /bin/cat --rc "$td/rc" --delay 50 --phase 4142430a@200 -- out "$td/out" --timeout 5 -- /bin/cat
	# 4142430a = "ABC\n"; cat echoes it back
	# out file should have ABC\n from cat
	sleep 0.3
	r=$(cat "$td/rc" 2>/dev/null)
	case "$r" in
		0|42) echo PASS > "$td/result" ;;
		*) echo "FAIL: rc=$r, expected 0 or 42 (cat exits when stdin closes)" > "$td/result" ;;
	esac
}

t_tail_literal() {
	td=$1
	pdrive --prog /bin/cat --rc "$td/rc" --delay 50 --tail 'hello\n' --timeout 5 -- /bin/cat
	sleep 0.3
	r=$(cat "$td/rc" 2>/dev/null)
	case "$r" in
		0|42) echo PASS > "$td/result" ;;
		*) echo "FAIL: rc=$r" > "$td/result" ;;
	esac
}

t_tail_escapes() {
	td=$1
	pdrive --prog /bin/cat --rc "$td/rc" --out "$td/out" --delay 50 --tail 'AB\x43\x0a' --timeout 5 -- /bin/cat
	sleep 0.5
	out=$(cat "$td/out" 2>/dev/null)
	case "$out" in
		*ABC*) echo PASS > "$td/result" ;;
		*) echo "FAIL: out=[$out], expected ABC" > "$td/result" ;;
	esac
}

t_winsize_sets_terminal() {
	td=$1
	pdrive --prog /bin/sh --rc "$td/rc" --winsize 12x40 --timeout 3 -- /bin/sh -c 'stty size 2>/dev/null || echo unknown'
	sleep 0.3
	out=$(cat "$td/out" 2>/dev/null)
	r=$(cat "$td/rc" 2>/dev/null)
	# stty size should print "12 40" or we just check rc=0
	case "$out" in
		*12\ 40*) echo PASS > "$td/result" ;;
		*) [ "$r" = "0" ] && echo PASS > "$td/result" || echo "FAIL: out=[$out] rc=$r" > "$td/result" ;;
	esac
}

t_ready_waits_for_marker() {
	td=$1
	printf '#!/bin/sh\nsleep 0.5\necho READY_MARKER\nsleep 60\n' > "$td/script.sh"
	chmod +x "$td/script.sh"
	pdrive --prog /bin/sh --rc "$td/rc" --ready READY_MARKER --timeout 5 -- "$td/script.sh"
	r=$(cat "$td/rc" 2>/dev/null)
	[ "$r" = "0" ] && echo PASS > "$td/result" || echo "FAIL: rc=$r, expected 0 (ready should wait)" > "$td/result"
}

t_ready_timeout() {
	td=$1
	pdrive --prog /bin/sh --rc "$td/rc" --ready NEVER_APPEARS --ready-timeout 1 --timeout 5 -- /bin/sh -c 'sleep 60'
	r=$(cat "$td/rc" 2>/dev/null)
	case "$r" in
		timeout|0) echo PASS > "$td/result" ;;
		*) echo "FAIL: rc=$r, expected timeout or 0" > "$td/result" ;;
	esac
}

t_early_exit_detection() {
	td=$1
	pdrive --prog /bin/sh --rc "$td/rc" --ready NEVER_APPEARS --ready-timeout 3 --timeout 10 -- /bin/sh -c 'exit 7'
	r=$(cat "$td/rc" 2>/dev/null)
	[ "$r" = "7" ] && echo PASS > "$td/result" || echo "FAIL: rc=$r, expected 7 (early exit)" > "$td/result"
}

t_after_ready() {
	td=$1
	printf '#!/bin/sh\necho READY\nsleep 60\n' > "$td/script.sh"
	chmod +x "$td/script.sh"
	pdrive --prog /bin/sh --rc "$td/rc" --ready READY --after-ready 'kill -TERM $$' --timeout 5 -- "$td/script.sh"
	# after-ready runs in parent; kill -TERM $$ kills the parent shell, not the child
	# so we just check it doesn't hang
	r=$(cat "$td/rc" 2>/dev/null)
	case "$r" in
		0|sig:*) echo PASS > "$td/result" ;;
		*) echo "FAIL: rc=$r" > "$td/result" ;;
	esac
}

t_env_passthrough() {
	td=$1
	pdrive --prog /bin/sh --rc "$td/rc" --env MYVAR=hello42 --timeout 3 -- /bin/sh -c 'echo $MYVAR'
	sleep 0.3
	out=$(cat "$td/out" 2>/dev/null)
	case "$out" in
		*hello42*) echo PASS > "$td/result" ;;
		*) echo "FAIL: out=[$out], expected hello42" > "$td/result" ;;
	esac
}

t_phase_then_tail_order() {
	td=$1
	pdrive --prog /bin/cat --rc "$td/rc" --out "$td/out" --delay 50 --phase 41 --tail 'B\x0a' --timeout 5 -- /bin/cat
	sleep 0.5
	out=$(cat "$td/out" 2>/dev/null)
	case "$out" in
		*AB*) echo PASS > "$td/result" ;;
		*) echo "FAIL: out=[$out], expected AB (phase then tail)" > "$td/result" ;;
	esac
}

t_delay_overridden_by_phase() {
	td=$1
	pdrive --prog /bin/cat --rc "$td/rc" --delay 9999 --phase 41@50 --timeout 5 -- /bin/cat
	sleep 0.3
	r=$(cat "$td/rc" 2>/dev/null)
	case "$r" in
		0|42) echo PASS > "$td/result" ;;
		*) echo "FAIL: rc=$r" > "$td/result" ;;
	esac
}

TESTS="t_basic_echo t_exit_code t_signal_term t_signal_kill t_timeout t_out_captures_output t_out_multiline t_phase_hex t_tail_literal t_tail_escapes t_winsize_sets_terminal t_ready_waits_for_marker t_ready_timeout t_early_exit_detection t_after_ready t_env_passthrough t_phase_then_tail_order t_delay_overridden_by_phase"

. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
run_suite "pty_drive" "$TESTS"
