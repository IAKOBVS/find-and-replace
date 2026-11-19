#!/bin/sh
# Compile and run every per-function unit test generated under tests/unit.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OUT=$(mktemp -d) || exit 1
trap 'rm -rf "$OUT"' EXIT

SRCS="main io traverse process terminal vim procfs grep_worker spsc spmc pipeline ui"
CFLAGS="-Itests/unit -Iinclude -I/usr/local/include -O0 -g -pthread -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable"
pass=0
fail=0
count=0

for f in tests/unit/src/*/*.c tests/unit/include/*/*.c; do
	[ -f "$f" ] || continue
	case "$f" in
	tests/unit/src/*/*) module=$(basename "$(dirname "$f")") ;;
	*) module= ;;
	esac
	name=$(basename "$f" .c)
	objs=""
	for m in $SRCS; do
		[ "$m" = main ] && continue
		[ "$m" = "$module" ] && continue
		objs="$objs $m.o"
	done
	out="$OUT/$module-$name"
	bin=""
	if cc $CFLAGS "$f" $objs -o "$out" -L/usr/local/lib -ljstr 2>"$OUT/$module-$name.err"; then
		bin=$out
	else
		fail=$((fail + 1))
		printf 'FAIL compile %s\n' "$f"
		head -5 "$OUT/$module-$name.err"
		continue
	fi
	count=$((count + 1))
	if timeout 10 "$bin" >"$OUT/$module-$name.out" 2>&1; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
		printf 'FAIL run %s\n' "$f"
		head -10 "$OUT/$module-$name.out"
	fi
done

printf '\n=== per-function units: %d passed, %d failed ===\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
