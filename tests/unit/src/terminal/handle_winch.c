#include "harness.h"
#include "../../../../src/terminal.c"
int
main(void)
{
	SPEC_SYMBOL(handle_winch);
	SECTION("positive");
	term_size_dirty = 0;
	handle_winch(SIGWINCH);
	CHECK(term_size_dirty == 1);
	SECTION("negative");
	term_size_dirty = 0;
	handle_winch(SIGINT);
	CHECK(term_size_dirty == 1);
	SECTION("edge");
	term_size_dirty = 1;
	handle_winch(SIGWINCH);
	CHECK(term_size_dirty == 1);
	cached_rows = 7;
	cached_cols = 11;
	term_size_dirty = 0;
	CHECK(terminal_rows() == 7);
	CHECK(terminal_cols() == 11);
	SECTION("fuzz");
	for (int i = 0; i < 64; ++i) {
		unsigned long v = unit_rng_next();
		term_size_dirty = (sig_atomic_t)(v & 1UL);
		handle_winch(SIGWINCH);
		CHECK(term_size_dirty == 1);
	}
	UNIT_DONE();
}
