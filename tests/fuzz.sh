#!/bin/sh
# Fuzz test: runs find-and-replace with randomish inputs, checks for crashes

PROG_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROG="$PROG_DIR/find-and-replace"
export LD_LIBRARY_PATH="$PROG_DIR/lib/jstring/build/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
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

	# Random flags: pick from expanded set including -Z/-z/-G
	case $((i % 16)) in
		0) flags='' ;;
		1) flags='-g' ;;
		2) flags='-R' ;;
		3) flags='-E' ;;
		4) flags='-I' ;;
		5) flags='-R -E' ;;
		6) flags='-R -I' ;;
		7) flags='-R -g' ;;
		8) flags='-Z' ;;
		9) flags='-z' ;;
		10) flags='-G' ;;
		11) flags='-R -Z' ;;
		12) flags='-R -z' ;;
		13) flags='-R -g -I' ;;
		14) flags='-gG' ;;
		15) flags='-Gg' ;;
	esac

	# Run via stdin
	printf '%s' "$input" | "$PROG" "$find" "$rplc" $flags > /dev/null 2>&1
	rc=$?
	if [ "$rc" -gt 127 ]; then
		red "CRASH (signal $((rc - 128))) on iteration $i (stdin)"
		FAIL=$((FAIL + 1))
	elif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
		red "UNEXPECTED EXIT CODE $rc on iteration $i (stdin)"
		FAIL=$((FAIL + 1))
	fi

	# Run with file input
	printf '%s' "$input" > "$td/f"
	printf '%s' "$input" | "$PROG" "$find" "$rplc" $flags "$td/f" > /dev/null 2>&1
	rc=$?
	if [ "$rc" -gt 127 ]; then
		red "CRASH (signal $((rc - 128))) on iteration $i (file mode)"
		FAIL=$((FAIL + 1))
	elif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
		red "UNEXPECTED EXIT CODE $rc on iteration $i (file mode)"
		FAIL=$((FAIL + 1))
	fi

	# In-place mode (no suffix)
	printf '%s' "$input" > "$td/f2"
	"$PROG" "$find" "$rplc" -i "$td/f2" > /dev/null 2>&1
	rc=$?
	if [ "$rc" -gt 127 ]; then
		red "CRASH (signal $((rc - 128))) on iteration $i (in-place)"
		FAIL=$((FAIL + 1))
	elif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
		red "UNEXPECTED EXIT CODE $rc on iteration $i (in-place)"
		FAIL=$((FAIL + 1))
	fi

	# In-place with backup suffix (every 3rd iteration)
	if [ $((i % 3)) -eq 0 ]; then
		printf '%s' "$input" > "$td/f3"
		"$PROG" "$find" "$rplc" -i.bak "$td/f3" > /dev/null 2>&1
		rc=$?
		if [ "$rc" -gt 127 ]; then
			red "CRASH (signal $((rc - 128))) on iteration $i (in-place .bak)"
			FAIL=$((FAIL + 1))
		elif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
			red "UNEXPECTED EXIT CODE $rc on iteration $i (in-place .bak)"
			FAIL=$((FAIL + 1))
		fi
	fi

	i=$((i + 1))
done

if [ "$FAIL" -eq 0 ]; then
	green "fuzz: $N iterations, 0 crashes"
else
	red "fuzz: $FAIL crashes in $N iterations"
fi
exit $((FAIL > 0))
