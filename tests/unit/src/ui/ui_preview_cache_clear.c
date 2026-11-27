#include "harness.h"
#include "../../../../src/ui.c"
int
main(void)
{
	SPEC_SYMBOL(ui_preview_cache_clear);
	SECTION("positive");
	G.preview_cache_valid = 1;
	G.preview_cache_matches = 7;
	preview_cache.size = 20;
	preview_cache.full = 1;
	ui_preview_cache_clear();
	CHECK(G.preview_cache_valid == 0);
	CHECK(G.preview_cache_matches == 7);
	CHECK(preview_cache.size == 20);
	SECTION("negative");
	G.preview_cache_valid = 0;
	ui_preview_cache_clear();
	CHECK(G.preview_cache_valid == 0);
	SECTION("edge");
	G.preview_cache_valid = 1;
	preview_cache.size = PREVIEW_CACHE_LINE_MAX;
	ui_preview_cache_clear();
	CHECK(G.preview_cache_valid == 0);
	SECTION("fuzz");
	for (int i = 0; i < 64; ++i) {
		unsigned long v = unit_rng_next();
		G.preview_cache_valid = (int)(v & 1UL);
		preview_cache.size = (size_t)(v % (PREVIEW_CACHE_LINE_MAX + 1));
		ui_preview_cache_clear();
		CHECK(G.preview_cache_valid == 0);
	}
	UNIT_DONE();
}
