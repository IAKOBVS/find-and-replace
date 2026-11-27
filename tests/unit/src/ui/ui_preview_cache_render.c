#include "harness.h"
#include "../../../../src/ui.c"
int
main(void)
{
	SPEC_SYMBOL(ui_preview_cache_render);
	SECTION("positive");
	G.preview_cache_valid = 1;
	preview_cache.size = 0;
	ui_preview_cache_render(0, 0, 13);
	SECTION("negative");
	G.preview_cache_valid = 0;
	ui_preview_cache_render(0, 0, 13);
	SECTION("edge");
	G.preview_cache_valid = 1;
	preview_cache.full = 1;
	ui_preview_cache_render(SIZE_MAX, SIZE_MAX, 0);
	SECTION("fuzz");
	for (int i = 0; i < 64; ++i) {
		unsigned long v = unit_rng_next();
		G.preview_cache_valid = 1;
		preview_cache.size = 0;
		ui_preview_cache_render((size_t)(v % 25), (size_t)(v >> 32) % 25, 13);
		CHECK(v == v);
	}
	UNIT_DONE();
}
