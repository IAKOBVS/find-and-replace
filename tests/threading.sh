#!/bin/sh
# Threaded recursive pipeline: traversal thread + worker pool (-j/--jobs).
# The pipeline must produce byte-identical output to the sequential path.
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

# Build a tree: DIR/ with SUBDEPTH levels of nested subdirs, FILES files per
# level, each containing "old" lines.
make_tree() {
	dir="$1"; depth="$2"; files="$3"
	mkdir -p "$dir"
	d="$dir"
	i=0
	while [ "$i" -lt "$depth" ]; do
		d="$d/sub$i"
		mkdir -p "$d"
		j=0
		while [ "$j" -lt "$files" ]; do
			printf 'old line %s\nanother old\n' "$j" > "$d/f$j.txt"
			j=$((j + 1))
		done
		i=$((i + 1))
	done
}

t_jobs_flag_basic() {
	td=$1; make_tree "$td/tree" 2 4
	"$PROG" old new -g -i -j4 -r "$td/tree" 2>/dev/null
	rc=$?
	n=$(grep -r --include='*.txt' -c 'new' "$td/tree" | awk -F: '{s+=$NF} END{print s}')
	m=$(grep -r --include='*.txt' -c 'old' "$td/tree" | awk -F: '{s+=$NF} END{print s}')
	# 2 levels x 4 files x 2 "old" lines per file.
	[ "$rc" -eq 0 ] && [ "$n" -eq 16 ] && [ "$m" -eq 0 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc new=$n old=$m" > "$td/result"
}

t_jobs_one() {
	td=$1; make_tree "$td/tree" 2 3
	"$PROG" old new -g -i -j1 -r "$td/tree" 2>/dev/null
	rc=$?
	n=$(grep -r --include='*.txt' -c 'new' "$td/tree" | awk -F: '{s+=$NF} END{print s}')
	# 2 levels x 3 files x 2 "old" lines per file.
	[ "$rc" -eq 0 ] && [ "$n" -eq 12 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc n=$n" > "$td/result"
}

t_jobs_long_form() {
	td=$1; make_tree "$td/tree" 1 3
	"$PROG" old new -g -i --jobs 3 -r "$td/tree" 2>/dev/null
	rc=$?
	n=$(grep -r --include='*.txt' -c 'new' "$td/tree" | awk -F: '{s+=$NF} END{print s}')
	# 1 level x 3 files x 2 "old" lines per file.
	[ "$rc" -eq 0 ] && [ "$n" -eq 6 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc n=$n" > "$td/result"
}

t_jobs_high_count_deadlock() {
	td=$1; make_tree "$td/tree" 2 4
	if command -v timeout >/dev/null 2>&1; then
		timeout 10 "$PROG" old new -g -i -j64 -r "$td/tree" 2>/dev/null
		rc=$?
	else
		"$PROG" old new -g -i -j64 -r "$td/tree" 2>/dev/null
		rc=$?
	fi
	n=$(grep -r --include='*.txt' -c 'new' "$td/tree" | awk -F: '{s+=$NF} END{print s}')
	[ "$rc" -eq 0 ] && [ "$n" -eq 16 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc n=$n" > "$td/result"
}

t_jobs_zero_rejected() {
	td=$1; rc=0; "$PROG" foo bar -j0 -r /dev/null > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: -j0 should exit non-zero (rc=$rc)" > "$td/result"
}

t_jobs_nan_rejected() {
	td=$1; rc=0; "$PROG" foo bar -jx -r /dev/null > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: -jx should exit non-zero (rc=$rc)" > "$td/result"
}

t_jobs_missing_arg() {
	td=$1; rc=0; "$PROG" foo bar --jobs > /dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ] && echo PASS > "$td/result" || echo "FAIL: --jobs without arg should exit non-zero (rc=$rc)" > "$td/result"
}

# stdout recursion must be deterministic and identical across job counts:
# the emitter releases results strictly in traversal order.
t_recursive_stdout_ordered() {
	td=$1; make_tree "$td/tree" 3 5
	"$PROG" old new -g -r -j8 "$td/tree" > "$td/out8" 2>/dev/null
	"$PROG" old new -g -r "$td/tree" > "$td/outseq" 2>/dev/null
	if cmp -s "$td/out8" "$td/outseq"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: -j8 stdout differs from sequential run" > "$td/result"
	fi
}

t_recursive_stdout_deterministic() {
	td=$1; make_tree "$td/tree" 3 6
	"$PROG" old new -g -r -j8 "$td/tree" > "$td/o1" 2>/dev/null
	"$PROG" old new -g -r -j8 "$td/tree" > "$td/o2" 2>/dev/null
	if cmp -s "$td/o1" "$td/o2"; then
		echo PASS > "$td/result"
	else
		echo "FAIL: two threaded runs differ" > "$td/result"
	fi
}

t_grep_recursive_threaded() {
	td=$1; make_tree "$td/tree" 2 3
	"$PROG" old --grep -r -j4 "$td/tree" > "$td/out" 2>/dev/null
	rc=$?
	lines=$(strip_ansi < "$td/out" | wc -l)
	matches=$(strip_ansi < "$td/out" | grep -c 'old')
	# 2 levels x 3 files x 2 "old" lines per file; every printed line is
	# prefixed FILE:LINE: by grep mode.
	[ "$rc" -eq 0 ] && [ "$lines" -eq 12 ] && [ "$matches" -eq 12 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc lines=$lines matches=$matches" > "$td/result"
}

t_grep_recursive_threaded_nomatch() {
	td=$1; make_tree "$td/tree" 1 2
	"$PROG" zzzznotfound --grep -q -r -j4 "$td/tree" > /dev/null 2>&1
	rc=$?
	[ "$rc" -eq 1 ] && echo PASS > "$td/result" || echo "FAIL: no match should exit 1 (rc=$rc)" > "$td/result"
}

# A per-file failure mid-tree must not stop the walk, and the total is still
# reported (same accumulation contract as the sequential path).
t_recursive_error_accumulation_threaded() {
	td=$1; mkdir -p "$td/sub"
	printf 'old\n' > "$td/sub/a"
	printf 'old\n' > "$td/sub/b"
	printf 'old\n' > "$td/sub/c"
	chmod 000 "$td/sub/b"
	rc=0; "$PROG" old new -g -i -j8 -r "$td/sub" > /dev/null 2> "$td/err" || rc=$?
	chmod 644 "$td/sub/b"
	ca=$(cat "$td/sub/a"); cb=$(cat "$td/sub/b"); cc=$(cat "$td/sub/c")
	case "$(cat "$td/err")" in
		*"file(s) failed during processing"*) msg=1 ;;
		*) msg=0 ;;
	esac
	[ "$rc" -ne 0 ] && [ "$ca" = 'new' ] && [ "$cb" = 'old' ] && [ "$cc" = 'new' ] && [ "$msg" -eq 1 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc a[$ca] b[$cb] c[$cc] msg=$msg" > "$td/result"
}

# Backup collision under threading: same fatal message + exit code as the
# sequential path, original file left untouched.
t_recursive_backup_collision_threaded() {
	td=$1; mkdir -p "$td/sub"
	printf 'aaa\n' > "$td/sub/f"
	printf 'collision\n' > "$td/sub/f.bak"
	rc=0; msg=$("$PROG" aaa replaced -g -i.bak -j4 -r "$td/sub" 2>&1 >/dev/null) || rc=$?
	content=$(cat "$td/sub/f")
	case "$msg" in
		*"already exists"*) m=1 ;;
		*) m=0 ;;
	esac
	[ "$rc" -ne 0 ] && [ "$m" -eq 1 ] && [ "$content" = 'aaa' ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc m=$m content=[$content]" > "$td/result"
}

t_many_files_stress() {
	td=$1; mkdir -p "$td/sub"
	i=0
	while [ "$i" -lt 300 ]; do
		printf 'old %s\n' "$i" > "$td/sub/f$i"
		i=$((i + 1))
	done
	"$PROG" old new -g -i -j8 -r "$td/sub" 2>/dev/null
	rc=$?
	n=$(grep -l 'new' "$td/sub"/f* 2>/dev/null | wc -l)
	[ "$rc" -eq 0 ] && [ "$n" -eq 300 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc replaced=$n/300" > "$td/result"
}

t_deep_tree_threaded() {
	td=$1; make_tree "$td/tree" 6 2
	"$PROG" old new -g -i -j8 -r "$td/tree" 2>/dev/null
	rc=$?
	n=$(grep -r --include='*.txt' -lc 'new' "$td/tree" 2>/dev/null | wc -l)
	# 6 levels x 2 files per level.
	[ "$rc" -eq 0 ] && [ "$n" -eq 12 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc files=$n/12" > "$td/result"
}

t_regex_backrefs_threaded() {
	td=$1; mkdir -p "$td/sub"
	printf 'hello world\n' > "$td/sub/f"
	"$PROG" '\\(hello\\) \\(world\\)' '\\2 \\1' -R -g -i -j4 -r "$td/sub" 2>/dev/null
	out=$(cat "$td/sub/f")
	[ "$out" = 'world hello' ] && echo PASS > "$td/result" || echo "FAIL: out=[$out]" > "$td/result"
}

# The tty collect path (grep TUI file cache) must also run through the
# threaded pipeline: traversal thread + reader threads, emitter caches in
# traversal order. Driven through a pty like the grep suite does.
# C driver (tests/pty_drive): waits for READY when given, else runs dry.
# A stray --noready from legacy call sites is ignored (unknown opt).
PDRIVE="$PROG_DIR/tests/pty_drive"
pdrive() {
	"$PDRIVE" --prog "$PROG" --out "$td/out" --rc "$td/rc" \
		--ready '-- [INSERT] --' "$@" >/dev/null 2>&1
}

strip_ansi_t() {
	sed 's/\x1b\[[0-9;]*m//g'
}

t_grep_tui_threaded_collect() {
	td=$1; make_tree "$td/tree" 1 3
	# Second Enter as a safety net: with streaming, results may arrive a
	# beat after the UI opens; an early Enter on an empty list is a no-op.
	pdrive --noready --phase 0d --phase 0d@600 --tail '' -- old x --grep -r -j4 "$td/tree"
	rc=$(cat "$td/rc" 2>/dev/null)
	# Repaints may duplicate rows; assert every cached line appeared.
	matches=$(strip_ansi_t < "$td/out" 2>/dev/null | grep -c 'old')
	[ "$rc" = "0" ] && [ "$matches" -ge 6 ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc matches=$matches" > "$td/result"
}

# Regression: clearing FIND (Ctrl-U) in the tty TUI used to segfault --
# the stream built an uncompiled zeroed regex / Two-Way for find_len == 0.
# Empty find now counts files but emits no lines (legacy grep parity).
t_grep_tui_empty_find_no_crash() {
	td=$1; make_tree "$td/tree" 1 3
	# 15 = Ctrl-U (clears FIND), then quit with Ctrl-D; no SIG prefix in rc.
	pdrive --noready --phase 1504 --tail '' -- old x --grep -r -j4 "$td/tree"
	rc=$(cat "$td/rc" 2>/dev/null)
	case "$rc" in
		sig:*|"") echo "FAIL: crashed/timeout rc=$rc" > "$td/result" ;;
		*) echo PASS > "$td/result" ;;
	esac
}

t_confirm_tui_threaded_collect() {
	td=$1; make_tree "$td/tree" 2 5
	pdrive --phase 0d --tail 'y\n' -- old new -c -i -r "$td/tree"
	rc=$(cat "$td/rc" 2>/dev/null)
	out=$(strip_ansi_t < "$td/out")
	case "$out" in
		*':new'*) m=1 ;;
		*) m=0 ;;
	esac
	[ "$rc" = "0" ] && [ "$m" = "1" ] && echo PASS > "$td/result" || echo "FAIL: rc=$rc preview=$m" > "$td/result"
}

TESTS="
t_jobs_flag_basic
t_jobs_one
t_jobs_long_form
t_jobs_high_count_deadlock
t_jobs_zero_rejected
t_jobs_nan_rejected
t_jobs_missing_arg
t_recursive_stdout_ordered
t_recursive_stdout_deterministic
t_grep_recursive_threaded
t_grep_recursive_threaded_nomatch
t_recursive_error_accumulation_threaded
t_recursive_backup_collision_threaded
t_many_files_stress
t_deep_tree_threaded
t_regex_backrefs_threaded
t_grep_tui_threaded_collect
t_grep_tui_empty_find_no_crash
t_confirm_tui_threaded_collect
"
run_suite "threaded recursive pipeline (-j/--jobs)" "$TESTS"
