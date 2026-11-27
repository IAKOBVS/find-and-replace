#include "harness.h"
#include "../../../../src/ui.c"
int
main(void)
{
	SPEC_SYMBOL(ui_preview_cache_covers);
	SECTION("positive");
	G.preview_cache_valid = 1;
	preview_cache.size = 20;
	preview_cache.full = 0;
	CHECK(ui_preview_cache_covers(5, 13) == 1);
	SECTION("negative");
	G.preview_cache_valid = 0;
	CHECK(ui_preview_cache_covers(0, 1) == 0);
	G.preview_cache_valid = 1;
	CHECK(ui_preview_cache_covers(20, 1) == 0);
	SECTION("edge");
	CHECK(ui_preview_cache_covers(0, 0) == 1);
	preview_cache.full = 1;
	CHECK(ui_preview_cache_covers(20, 1) == 1);
	SECTION("fuzz");
	for (int i = 0; i < 64; ++i) {
		unsigned long v = unit_rng_next();
		preview_cache.full = 0;
		CHECK(ui_preview_cache_covers((size_t)(v % 25), 13) == (v % 25 < 20));
	}
	UNIT_DONE();
}
