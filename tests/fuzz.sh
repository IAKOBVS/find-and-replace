#!/bin/sh
# Fuzz test: runs find-and-replace with randomish inputs, checks for crashes

PROG="$(cd "$(dirname "$0")/.." && pwd)/find-and-replace"
N=${1:-500}
FAIL=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

td=$(mktemp -d)
trap 'rm -rf "$td"' EXIT

randstr() {
	LC_ALL=C tr -dc 'A-Za-z0-9 \t\n_+*?.[(){}|^$\\-/'"'"'"' < /dev/urandom 2>/dev/null \
		| head -c "$1"
}

printf '\n=== fuzz tests (%d iterations) ===\n\n' "$N"

i=0
while [ "$i" -lt "$N" ]; do
	find=$(randstr $(( (i % 47) + 1 )))
	rplc=$(randstr $(( (i % 31) + 1 )))
	input=$(randstr $(( (i % 199) + 1 )))

	# Random flags:
	#   pick 0-2 from: -g -R -E -I -z
	flags=''
	case $((i % 8)) in
		0) flags='' ;;
		1) flags='-g' ;;
		2) flags='-R' ;;
		3) flags='-E' ;;
		4) flags='-I' ;;
		5) flags='-R -E' ;;
		6) flags='-R -I' ;;
		7) flags='-R -g' ;;
	esac

	# Run via stdin
	printf '%s' "$input" | "$PROG" "$find" "$rplc" $flags > /dev/null 2>&1
	rc=$?
	if [ "$rc" -gt 127 ]; then
		red "CRASH (signal $((rc - 128))) on iteration $i"
		FAIL=$((FAIL + 1))
	fi

	# Run with file input
	printf '%s' "$input" > "$td/f"
	printf '%s' "$input" | "$PROG" "$find" "$rplc" $flags "$td/f" > /dev/null 2>&1
	rc=$?
	if [ "$rc" -gt 127 ]; then
		red "CRASH (signal $((rc - 128))) on iteration $i (file mode)"
		FAIL=$((FAIL + 1))
	fi

	# In-place mode
	printf '%s' "$input" > "$td/f2"
	"$PROG" "$find" "$rplc" -i "$td/f2" > /dev/null 2>&1
	rc=$?
	if [ "$rc" -gt 127 ]; then
		red "CRASH (signal $((rc - 128))) on iteration $i (in-place)"
		FAIL=$((FAIL + 1))
	fi

	i=$((i + 1))
done

if [ "$FAIL" -eq 0 ]; then
	green "fuzz: $N iterations, 0 crashes"
else
	red "fuzz: $FAIL crashes in $N iterations"
fi
exit $((FAIL > 0))
