#include "harness.h"
#include "../../../../src/ui.c"
int
main(void)
{
	SPEC_SYMBOL(ui_preview_capture_begin);
	SECTION("positive");
	G.preview_cache_valid = 1;
	G.preview_lines_printed = 9;
	G.preview_full = 1;
	ui_preview_capture_begin();
	CHECK(G.preview_cache_valid == 0);
	CHECK(G.preview_lines_printed == 0);
	CHECK(G.preview_full == 0);
	SECTION("negative");
	ui_preview_capture_begin();
	CHECK(G.preview_cache_matches == 0);
	CHECK(G.preview_cache_files == 0);
	SECTION("edge");
	G.max_preview_lines = 0;
	ui_preview_capture_begin();
	CHECK(G.total_lines == 0);
	SECTION("fuzz");
	for (int i = 0; i < 64; ++i) {
		unsigned long v = unit_rng_next();
		ui_preview_capture_begin();
		CHECK(v == v);
	}
	UNIT_DONE();
}
