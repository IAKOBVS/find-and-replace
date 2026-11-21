#include "harness.h"
#include "../../../../src/pipeline.c"
int
main(void)
{
	SPEC_SYMBOL(pipeline_start);

	SECTION("start with 4 workers uses static storage");
	pipeline_set_workers(4);
	CHECK(pipeline_start() == 0);
	CHECK(pipeline_worker_count() == 4);
	CHECK(pipeline_uses_static_workers() != 0);
	pipeline_shutdown();

	SECTION("start with 12 workers uses heap storage");
	pipeline_set_workers(12);
	CHECK(pipeline_start() == 0);
	CHECK(pipeline_worker_count() == 12);
	CHECK(pipeline_uses_static_workers() == 0);
	pipeline_shutdown();

	SECTION("start with 8 workers stays on the static threshold");
	pipeline_set_workers(8);
	CHECK(pipeline_start() == 0);
	CHECK(pipeline_worker_count() == 8);
	CHECK(pipeline_uses_static_workers() != 0);
	pipeline_shutdown();

	SECTION("shutdown resets state so repeated starts work");
	for (int i = 0; i < 3; ++i) {
		pipeline_set_workers(4);
		CHECK(pipeline_start() == 0);
		CHECK(pipeline_worker_count() == 4);
		CHECK(pipeline_uses_static_workers() != 0);
		pipeline_shutdown();
	}

	UNIT_DONE();
}
