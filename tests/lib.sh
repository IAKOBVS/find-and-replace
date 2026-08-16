PROG_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROG="$PROG_DIR/find-and-replace"
export LD_LIBRARY_PATH="$PROG_DIR/lib/jstring/build/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
PASS=0
FAIL=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

td_root=$(mktemp -d)
trap 'rm -rf "$td_root"' EXIT

# Per-suite test-level parallelism cap. Default 512 lets each suite run all of
# its tests concurrently; override with FAR_MAX_JOBS (e.g. low-ulimit systems).
MAX_JOBS=${FAR_MAX_JOBS:-512}
[ "$MAX_JOBS" -ge 1 ] || MAX_JOBS=1

report_result() {
	t="$1"
	r=$(cat "$td_root/$t/result" 2>/dev/null)
	case "$r" in
		PASS*) PASS=$((PASS+1)); green "PASS $t" ;;
		FAIL*) FAIL=$((FAIL+1)); red "FAIL $t (${r#FAIL: })" ;;
		*)     FAIL=$((FAIL+1)); red "FAIL $t (no result)" ;;
	esac
}

run_tests() {
	TESTS="$1"
	launched=""
	count=0
	for t in $TESTS; do
		(
			mkdir -p "$td_root/$t"
			if ! "$t" "$td_root/$t"; then
				[ -s "$td_root/$t/result" ] || echo "FAIL: test exited with error" > "$td_root/$t/result"
			fi
			[ -s "$td_root/$t/result" ] || echo "FAIL: no result written" > "$td_root/$t/result"
		) &
		launched="$launched $t"
		count=$((count + 1))
		if [ "$count" -ge "$MAX_JOBS" ]; then
			wait_for_results "$launched"
			launched=""
			count=0
		fi
	done
	[ "$count" -gt 0 ] && wait_for_results "$launched"
}

wait_for_results() {
	# Poll the result files of the given tests, printing each test's outcome
	# the moment its result appears, then reap the finished subshells.
	left="$1"
	while [ -n "$left" ]; do
		rest=""
		for t in $left; do
			if [ -s "$td_root/$t/result" ]; then
				report_result "$t"
			else
				rest="$rest $t"
			fi
		done
		left="$rest"
		[ -n "$left" ] && sleep 0.05
	done
	wait
}

run_suite() {
	name="$1"
	TESTS="$2"
	PASS=0
	FAIL=0
	printf '\n=== %s ===\n\n' "$name"
	run_tests "$TESTS"
	printf '\n=== %s: %d passed, %d failed ===\n' "$name" "$PASS" "$FAIL"
	[ "$FAIL" -eq 0 ]
}
