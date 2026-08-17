#!/bin/sh
# Fuzz test: runs find-and-replace with randomish inputs, checks for crashes.
# Iterations run in parallel (capped at FUZZ_MAX_JOBS).

PROG_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROG="$PROG_DIR/find-and-replace"
export LD_LIBRARY_PATH="$PROG_DIR/lib/jstring/build/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
N=${1:-500}
ncpu() { nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4; }
_cpu=$(ncpu)
FUZZ_MAX_JOBS=${FAR_FUZZ_MAX_JOBS:-$((_cpu * 2))}
[ "$FUZZ_MAX_JOBS" -ge 1 ] || FUZZ_MAX_JOBS=1

td=$(mktemp -d)
trap 'rm -rf "$td"' EXIT

randstr() {
	LC_ALL=C tr -dc 'A-Za-z0-9 \t\n_+*?.[(){}|^$\\-/'"'"'"' < /dev/urandom 2>/dev/null \
		| head -c "$1"
}

run_one() {
	local i=$1 td=$2 PROG=$3
	local itd="$td/$i"
	mkdir -p "$itd"
	local find rplc input flags rc
	find=$(randstr $(( (i % 47) + 1 )))
	rplc=$(randstr $(( (i % 31) + 1 )))
	input=$(randstr $(( (i % 199) + 1 )))

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

	# stdin
	printf '%s' "$input" | "$PROG" "$find" "$rplc" $flags > /dev/null 2>&1
	rc=$?
	if [ "$rc" -gt 127 ]; then
		echo "CRASH signal $((rc - 128)) iteration $i stdin" > "$itd/result"
		return
	elif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
		echo "BADRC $rc iteration $i stdin" > "$itd/result"
		return
	fi

	# file
	printf '%s' "$input" > "$itd/f"
	printf '%s' "$input" | "$PROG" "$find" "$rplc" $flags "$itd/f" > /dev/null 2>&1
	rc=$?
	if [ "$rc" -gt 127 ]; then
		echo "CRASH signal $((rc - 128)) iteration $i file" > "$itd/result"
		return
	elif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
		echo "BADRC $rc iteration $i file" > "$itd/result"
		return
	fi

	# in-place
	printf '%s' "$input" > "$itd/f2"
	"$PROG" "$find" "$rplc" -i "$itd/f2" > /dev/null 2>&1
	rc=$?
	if [ "$rc" -gt 127 ]; then
		echo "CRASH signal $((rc - 128)) iteration $i inplace" > "$itd/result"
		return
	elif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
		echo "BADRC $rc iteration $i inplace" > "$itd/result"
		return
	fi

	# in-place with backup
	if [ $((i % 3)) -eq 0 ]; then
		printf '%s' "$input" > "$itd/f3"
		"$PROG" "$find" "$rplc" -i.bak "$itd/f3" > /dev/null 2>&1
		rc=$?
		if [ "$rc" -gt 127 ]; then
			echo "CRASH signal $((rc - 128)) iteration $i inplace-bak" > "$itd/result"
			return
		elif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
			echo "BADRC $rc iteration $i inplace-bak" > "$itd/result"
			return
		fi
	fi

	echo "OK" > "$itd/result"
}

printf '\n=== fuzz tests (%d iterations, %d jobs) ===\n\n' "$N" "$FUZZ_MAX_JOBS"

launched=""
count=0
i=0
while [ "$i" -lt "$N" ]; do
	run_one "$i" "$td" "$PROG" &
	launched="$launched $i"
	count=$((count + 1))
	if [ "$count" -ge "$FUZZ_MAX_JOBS" ]; then
		wait
		for j in $launched; do
			r=$(cat "$td/$j/result" 2>/dev/null)
			case "$r" in
				CRASH*) printf '\033[31m%s\033[0m\n' "$r"; FAIL=$((FAIL + 1)) ;;
				BADRC*) printf '\033[31m%s\033[0m\n' "$r"; FAIL=$((FAIL + 1)) ;;
			esac
		done
		launched=""
		count=0
	fi
	i=$((i + 1))
done
if [ "$count" -gt 0 ]; then
	wait
	for j in $launched; do
		r=$(cat "$td/$j/result" 2>/dev/null)
		case "$r" in
			CRASH*) printf '\033[31m%s\033[0m\n' "$r"; FAIL=$((FAIL + 1)) ;;
			BADRC*) printf '\033[31m%s\033[0m\n' "$r"; FAIL=$((FAIL + 1)) ;;
		esac
	done
fi

if [ "${FAIL:-0}" -eq 0 ]; then
	printf '\033[32mfuzz: %d iterations, 0 crashes\033[0m\n' "$N"
else
	printf '\033[31mfuzz: %d crashes in %d iterations\033[0m\n' "$FAIL" "$N"
fi
exit $((FAIL > 0))
