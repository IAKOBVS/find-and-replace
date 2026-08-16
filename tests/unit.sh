#!/bin/sh
# Unit tests: fake /proc/meminfo via LD_PRELOAD to exercise get_free_ram_size
# branches (open/read failure, MemAvailable parsing, edge-case parsing) and
# the pass-2 disk re-read when a file's content is not cached.

. "$(dirname "$0")/lib.sh"

SHIM="$td_root/fake_meminfo.so"
cc -shared -fPIC -O2 -o "$SHIM" "$(dirname "$0")/fake_meminfo.c" -ldl 2>/dev/null || {
	echo "FAIL: could not compile fake_meminfo shim" > "$td_root/shim.result"
	echo "FAIL: could not compile fake_meminfo shim"
	exit 1
}

# Run the tool non-interactively through the -c confirm pass with fake meminfo.
# $1 = find, $2 = replace, $3 = file path; env: FAKE_MEMINFO / FAKE_MEMINFO_*_FAIL
run_confirm() {
	find_="$1"; rplc_="$2"; f_="$3"
	printf 'y\n' | LD_PRELOAD="$SHIM" "$PROG" "$find_" "$rplc_" -c -i "$f_" > /dev/null 2>&1
}

t_meminfo_avail() {
	td=$1
	printf 'hello world\n' > "$td/f"
	FAKE_MEMINFO="MemTotal:   1000000 kB
MemFree:    50000 kB
MemAvailable:  300000 kB
Buffers:    100 kB
" run_confirm hello goodbye "$td/f"
	if [ "$(cat "$td/f")" = 'goodbye world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: replacement did not happen (got [$(cat "$td/f")])" > "$td/result"
	fi
}

t_meminfo_edge_parsing() {
	td=$1
	printf 'hello world\n' > "$td/f"
	# Leading/trailing spaces in key and value, blank line, no-colon line,
	# no trailing newline on the last line (procfs lines 19-21/28/33/35/41-42).
	FAKE_MEMINFO="  MemTotal :  100000 

NoColonLine
MemAvailable:  300000  " run_confirm hello goodbye "$td/f"
	if [ "$(cat "$td/f")" = 'goodbye world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: replacement did not happen with edge meminfo (got [$(cat "$td/f")])" > "$td/result"
	fi
}

t_meminfo_no_avail_reload() {
	td=$1
	printf 'hello world\n' > "$td/f"
	# No MemAvailable: free_ram stays 0, cache_max becomes 0, so the content
	# is not cached and pass 2 must re-read the file from disk (main.c).
	FAKE_MEMINFO="MemTotal:   1000000 kB
MemFree:    50000 kB
" run_confirm hello goodbye "$td/f"
	if [ "$(cat "$td/f")" = 'goodbye world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: re-read replacement did not happen (got [$(cat "$td/f")])" > "$td/result"
	fi
}

t_meminfo_small_cache_reload() {
	td=$1
	i=0; : > "$td/f"
	while [ $i -lt 20000 ]; do printf 'aaaaaaaaaaaaaaaaa\n' >> "$td/f"; i=$((i + 1)); done
	printf 'hello world\n' >> "$td/f"
	# 200 kB file, 100 kB cache_max: content not cached, pass 2 re-reads disk.
	FAKE_MEMINFO="MemAvailable: 100 kB
" run_confirm hello goodbye "$td/f"
	if [ "$(grep -c '^goodbye world$' "$td/f")" -eq 1 ] && [ "$(grep -c '^hello world$' "$td/f")" -eq 0 ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: small-cache re-read replacement did not happen" > "$td/result"
	fi
}

t_meminfo_open_fail() {
	td=$1
	printf 'hello world\n' > "$td/f"
	# open fails: get_free_ram_size falls back to 1 GiB, caching works normally.
	FAKE_MEMINFO_OPEN_FAIL=1 run_confirm hello goodbye "$td/f"
	if [ "$(cat "$td/f")" = 'goodbye world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: replacement did not happen when meminfo open fails (got [$(cat "$td/f")])" > "$td/result"
	fi
}

t_meminfo_read_fail() {
	td=$1
	printf 'hello world\n' > "$td/f"
	# read fails: get_free_ram_size falls back to 1 GiB.
	FAKE_MEMINFO_READ_FAIL=1 run_confirm hello goodbye "$td/f"
	if [ "$(cat "$td/f")" = 'goodbye world' ]; then
		echo PASS > "$td/result"
	else
		echo "FAIL: replacement did not happen when meminfo read fails (got [$(cat "$td/f")])" > "$td/result"
	fi
}

TESTS="t_meminfo_avail t_meminfo_edge_parsing t_meminfo_no_avail_reload t_meminfo_small_cache_reload t_meminfo_open_fail t_meminfo_read_fail"

run_suite "unit" "$TESTS"
