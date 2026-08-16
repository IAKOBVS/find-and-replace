#!/bin/sh
# Unified runner for all deterministic test suites.
# Runs each suite in order, streaming each test's PASS/FAIL to the terminal
# as it completes (each suite keeps its own internal batch-wait jobserver).

DIR="$(cd "$(dirname "$0")" && pwd)"
fail=0
for suite in basic flags regex files errors io escape empty misc edge-cases complex confirm unit grep; do
	if "$DIR/${suite}.sh"; then
		printf '\033[32mPASS\033[0m %s\n' "$suite"
	else
		printf '\033[31mFAIL\033[0m %s\n' "$suite"
		fail=$((fail + 1))
	fi
done

printf '\n=== %d suites passed, %d failed ===\n' $((14 - fail)) "$fail"
exit $((fail > 0 ? 1 : 0))
