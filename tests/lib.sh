PROG_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROG="$PROG_DIR/find-and-replace"
export LD_LIBRARY_PATH="$PROG_DIR/lib/jstring/build/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
PASS=0
FAIL=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

td_root=$(mktemp -d)
trap 'rm -rf "$td_root"' EXIT

MAX_JOBS=32

run_tests() {
	TESTS="$1"
	count=0
	for t in $TESTS; do
		(
			mkdir -p "$td_root/$t"
			"$t" "$td_root/$t"
		) &
		count=$((count + 1))
		if [ "$count" -ge "$MAX_JOBS" ]; then
			wait
			count=0
		fi
	done
	[ "$count" -gt 0 ] && wait
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
