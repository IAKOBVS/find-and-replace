#include "harness.h"
#include "../../../../src/pipeline.c"
int
main(void)
{
	SPEC_SYMBOL(pipeline_uses_static_workers);

	SECTION("safe before any start reports the default static choice");
	CHECK(pipeline_uses_static_workers() != 0);
	CHECK(pipeline_uses_static_workers() != 0);

	SECTION("nonzero becomes zero after starting with 12 workers");
	pipeline_set_workers(12);
	CHECK(pipeline_start() == 0);
	CHECK(pipeline_worker_count() == 12);
	CHECK(pipeline_uses_static_workers() == 0);
	pipeline_shutdown();

	SECTION("zero becomes nonzero after shutdown and start with 4 workers");
	pipeline_set_workers(4);
	CHECK(pipeline_start() == 0);
	CHECK(pipeline_worker_count() == 4);
	CHECK(pipeline_uses_static_workers() != 0);
	pipeline_shutdown();

	SECTION("the predicate tracks each fresh start without drifting");
	pipeline_set_workers(12);
	CHECK(pipeline_start() == 0);
	CHECK(pipeline_uses_static_workers() == 0);
	CHECK(pipeline_uses_static_workers() == 0);
	pipeline_shutdown();
	pipeline_set_workers(8);
	CHECK(pipeline_start() == 0);
	CHECK(pipeline_uses_static_workers() != 0);
	pipeline_shutdown();

	UNIT_DONE();
}
