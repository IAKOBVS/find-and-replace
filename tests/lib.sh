PROG_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROG="$PROG_DIR/find-and-replace"
export LD_LIBRARY_PATH="$PROG_DIR/lib/jstring/build/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
PASS=0
FAIL=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

td_root=$(mktemp -d)
trap 'rm -rf "$td_root"' EXIT

NP=$(nproc 2>/dev/null || echo 2)

if [ ! -x "$PROG_DIR/tests/pty_driver" ] || [ ! -x "$PROG_DIR/tests/err_helper" ]; then
	(
		cc -Wall -Wextra -pedantic "$PROG_DIR/tests/err_helper.c" -o "$PROG_DIR/tests/err_helper" &
		cc -Wall -Wextra -pedantic "$PROG_DIR/tests/pty_driver.c" -o "$PROG_DIR/tests/pty_driver" &
		wait
	)
fi

run_tests() {
	TESTS="$1"
	fifo="$td_root/fifo_lib"
	mkfifo "$fifo"
	exec 3<>"$fifo"
	rm -f "$fifo"

	i=0
	while [ "$i" -lt "$NP" ]; do
		echo >&3
		i=$((i + 1))
	done

	for t in $TESTS; do
		read -r _ <&3
		(
			mkdir -p "$td_root/$t"
			"$t" "$td_root/$t"
			echo >&3
		) &
	done
	wait
	exec 3>&-
}

collect_results() {
	TESTS="$1"
	for t in $TESTS; do
		r=$(cat "$td_root/$t/result" 2>/dev/null)
		case "$r" in
			PASS*) PASS=$((PASS+1)); green PASS ;;
			FAIL*) FAIL=$((FAIL+1)); red "FAIL (${r#FAIL: })" ;;
			*)     FAIL=$((FAIL+1)); red "FAIL ($t: no result)" ;;
		esac
	done
}

run_suite() {
	name="$1"
	TESTS="$2"
	printf '\n=== %s ===\n\n' "$name"
	run_tests "$TESTS"
	collect_results "$TESTS"
	printf '\n=== %s: %d passed, %d failed ===\n' "$name" "$PASS" "$FAIL"
	[ "$FAIL" -eq 0 ]
}
