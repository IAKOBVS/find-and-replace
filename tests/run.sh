#!/bin/sh
# Unified runner for all deterministic test suites.
# Launches suites in parallel capped at nproc using a FIFO job server.

DIR="$(cd "$(dirname "$0")" && pwd)"
NP=$(nproc 2>/dev/null || echo 2)
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
fail=0

SUITES="basic flags regex files errors io escape empty misc edge-cases complex confirm"

fifo="$tmp/fifo_run"
mkfifo "$fifo"
exec 3<>"$fifo"
rm -f "$fifo"

i=0
while [ "$i" -lt "$NP" ]; do
	echo >&3
	i=$((i + 1))
done

for suite in $SUITES; do
	read -r _ <&3
	(
		"$DIR/${suite}.sh" > /dev/null 2>&1
		echo $? > "$tmp/$suite.rc"
		echo >&3
	) &
done
wait
exec 3>&-

for suite in $SUITES; do
	read rc < "$tmp/$suite.rc" 2>/dev/null || rc=1
	if [ "$rc" -ne 0 ]; then
		printf '\033[31mFAIL\033[0m %s\n' "$suite"
		fail=$((fail + 1))
	else
		printf '\033[32mPASS\033[0m %s\n' "$suite"
	fi
done

printf '\n=== %d suites passed, %d failed ===\n' $((12 - fail)) "$fail"
exit $((fail > 0 ? 1 : 0))
