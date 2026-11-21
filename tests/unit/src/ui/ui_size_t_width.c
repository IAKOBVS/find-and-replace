#include "harness.h"
#include <stdint.h>
#include "../../../../src/ui.c"
int main(void)
{
	CHECK(ui_size_t_width(0) == 1);
	CHECK(ui_size_t_width(9) == 1);
	CHECK(ui_size_t_width(10) == 2);
	CHECK(ui_size_t_width(99) == 2);
	CHECK(ui_size_t_width(100) == 3);
	CHECK(ui_size_t_width(12345) == 5);
	CHECK(ui_size_t_width(SIZE_MAX) == 20);
	for (unsigned long v = unit_rng_next(); v > 0; v >>= 4)
		CHECK(ui_size_t_width((size_t)v) >= 1);
	UNIT_DONE();
}
