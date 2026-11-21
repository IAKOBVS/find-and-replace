#include "harness.h"
#include <stdlib.h>
#include "../../../../src/pipeline.c"
int main(void)
{
	unsetenv("FAR_THREADS");
	CHECK(default_workers() >= 1);
	setenv("FAR_THREADS", "7", 1);
	CHECK(default_workers() == 7);
	setenv("FAR_THREADS", "0", 1);
	CHECK(default_workers() >= 1);
	setenv("FAR_THREADS", "nope", 1);
	CHECK(default_workers() >= 1);
	unsetenv("FAR_THREADS");
	UNIT_DONE();
}
