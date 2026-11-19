#!/bin/sh
# Shared helpers for the top-level sanitizer test scripts.

sanitizer_build() {
	kind=$1
	dir=$2
	rm -rf "$dir"
	case "$kind" in
	tsan)
		make BUILD_DIR="$dir" TEST_BIN_DIR="$dir/tests" TSAN=1 \
			EXTRA_CFLAGS='-fsanitize=undefined -fno-omit-frame-pointer' \
			LDFLAGS='-L/usr/local/lib -pthread -fsanitize=thread,undefined' \
			compile
		;;
	asan)
		make BUILD_DIR="$dir" TEST_BIN_DIR="$dir/tests" \
			OPT='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
			LDFLAGS='-L/usr/local/lib -pthread -fsanitize=address,undefined' \
			compile
		;;
	*)
		echo "unknown sanitizer: $kind" >&2
		return 1
		;;
	esac
}

sanitizer_run_unit() {
	kind=$1
	dir=$2
	absdir=$(cd "$dir" && pwd) || return 1
	fail=0
	for t in spsc spmc pipeline; do
		test_bin="$absdir/tests/${t}_unit"
		if [ ! -x "$test_bin" ]; then
			echo "FAIL: missing $test_bin" >&2
			fail=1
			continue
		fi
		echo "=== ${kind}+ubsan unit: $t"
		case "$kind" in
		tsan)
			TSAN_OPTIONS=halt_on_error=1 \
			UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
			"$test_bin" || fail=1
			;;
		asan)
			ASAN_OPTIONS=halt_on_error=1:detect_leaks=1 \
			UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
			"$test_bin" || fail=1
			;;
		esac
	done
	return "$fail"
}

sanitizer_run_integration() {
	kind=$1
	dir=$2
	absdir=$(cd "$dir" && pwd) || return 1
	echo "=== ${kind}+ubsan integration"
	case "$kind" in
	tsan)
		PROG="$absdir/find-and-replace" \
		PIPELINE_TEST_BIN_DIR="$absdir/tests" \
		FAR_SKIP_UNIT_SHELL=1 \
		FAR_SKIP_TESTS="t_confirm_interactive_garbage_preview_cleared t_confirm_interactive_scroll_past_visend t_grep_interactive_vim_mode" \
		TSAN_OPTIONS=halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		./tests/run.sh
		;;
	asan)
		PROG="$absdir/find-and-replace" \
		PIPELINE_TEST_BIN_DIR="$absdir/tests" \
		FAR_SKIP_UNIT_SHELL=1 \
		FAR_SKIP_TESTS="t_pipeline_prompt_write_error" \
		ASAN_OPTIONS=halt_on_error=1:detect_leaks=0 \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		./tests/run.sh
		;;
	esac
}
