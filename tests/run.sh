#!/bin/sh
# Unified runner for all deterministic test suites.
# Launches suites in parallel capped at nproc, collects per-suite exit codes.

DIR="$(cd "$(dirname "$0")" && pwd)"
NP=$(nproc 2>/dev/null || echo 2)
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
fail=0

count=0
for suite in basic flags regex files errors io escape empty misc edge-cases complex confirm grep; do
	("$DIR/${suite}.sh" > /dev/null 2>&1; echo $? > "$tmp/$suite.rc") &
	count=$((count + 1))
	if [ "$count" -ge "$NP" ]; then
		wait
		count=0
	fi
done
[ "$count" -gt 0 ] && wait

for suite in basic flags regex files errors io escape empty misc edge-cases complex confirm grep; do
	read rc < "$tmp/$suite.rc"
	if [ "$rc" -ne 0 ]; then
		printf '\033[31mFAIL\033[0m %s\n' "$suite"
		fail=$((fail + 1))
	else
		printf '\033[32mPASS\033[0m %s\n' "$suite"
	fi
done

printf '\n=== %d suites passed, %d failed ===\n' $((13 - fail)) "$fail"
exit $((fail > 0 ? 1 : 0))
