#include "harness.h"
#include "../../../../src/ui.c"
int main(void)
{
	line_counter_ty st;
	line_counter_init(&st, "a\nb\nc");
	CHECK(line_counter_get(&st, 0) == 1);
	CHECK(line_counter_get(&st, 2) == 2);
	CHECK(line_counter_get(&st, 4) == 3);
	CHECK(line_counter_get(&st, 1) == 1);
	CHECK(line_counter_get(&st, 5) == 3);
	UNIT_DONE();
}
