#include "harness.h"
#include "../../../../src/ui.c"
int
main(void)
{
	SPEC_SYMBOL(ui_preview_capture_end);
	SECTION("positive");
	ui_preview_capture_begin();
	G.max_preview_lines = 10;
	ui_preview_capture_end(7, 3);
	CHECK(G.preview_cache_valid == 1);
	CHECK(G.preview_cache_matches == 7);
	CHECK(G.preview_cache_files == 3);
	CHECK(G.preview_cache_omitted == 0);
	SECTION("negative");
	ui_preview_capture_begin();
	G.preview_lines_printed = 11;
	ui_preview_capture_end(0, 0);
	CHECK(G.preview_cache_omitted == 1);
	SECTION("edge");
	ui_preview_capture_begin();
	G.max_preview_lines = 0;
	ui_preview_capture_end(0, 0);
	CHECK(G.preview_cache_valid == 1);
	SECTION("fuzz");
	for (int i = 0; i < 64; ++i) {
		unsigned long v = unit_rng_next();
		ui_preview_capture_begin();
		ui_preview_capture_end((size_t)v, (size_t)(v >> 32));
		CHECK(G.preview_cache_valid == 1);
	}
	UNIT_DONE();
}
