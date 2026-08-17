#!/bin/sh
# Unified runner for all deterministic test suites.
# Runs suites in parallel (capped at SUITE_MAX_JOBS), streaming each test's
# PASS/FAIL to the terminal as it completes.

DIR="$(cd "$(dirname "$0")" && pwd)"
ncpu() { nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4; }
_cpu=$(ncpu)
SUITE_MAX_JOBS=${FAR_SUITE_MAX_JOBS:-$((_cpu > 4 ? 4 : _cpu))}
[ "$SUITE_MAX_JOBS" -ge 1 ] || SUITE_MAX_JOBS=1

fail=0
launched=""
count=0
wait_suites() {
	for s in $launched; do
		wait
		rc=$?
		if [ "$rc" -eq 0 ]; then
			printf '\033[32mPASS\033[0m %s\n' "$s"
		else
			printf '\033[31mFAIL\033[0m %s\n' "$s"
			fail=$((fail + 1))
		fi
	done
	launched=""
	count=0
}

for suite in basic flags regex files errors io escape empty misc edge-cases complex confirm unit grep; do
	"$DIR/${suite}.sh" &
	launched="$launched $suite"
	count=$((count + 1))
	if [ "$count" -ge "$SUITE_MAX_JOBS" ]; then
		wait_suites
	fi
done
[ "$count" -gt 0 ] && wait_suites

printf '\n=== %d suites passed, %d failed ===\n' $((14 - fail)) "$fail"
exit $((fail > 0 ? 1 : 0))
