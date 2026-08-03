#!/bin/sh
# Unified runner for all deterministic test suites.
# Launches all suites in parallel, collects per-suite exit codes.

DIR="$(cd "$(dirname "$0")" && pwd)"
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
fail=0

for suite in basic flags regex files errors io escape empty misc edge-cases complex; do
	("$DIR/${suite}.sh" > /dev/null 2>&1; echo $? > "$tmp/$suite.rc") &
done
wait

for suite in basic flags regex files errors io escape empty misc edge-cases complex; do
	read rc < "$tmp/$suite.rc"
	if [ "$rc" -ne 0 ]; then
		printf '\033[31mFAIL\033[0m %s\n' "$suite"
		fail=$((fail + 1))
	else
		printf '\033[32mPASS\033[0m %s\n' "$suite"
	fi
done

printf '\n=== %d suites passed, %d failed ===\n' $((11 - fail)) "$fail"
exit $((fail > 0 ? 1 : 0))
