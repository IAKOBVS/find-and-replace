#include "harness.h"
#include "../../../../src/ui.c"
int main(void)
{
	line_counter_ty st;
	line_counter_init(&st, "a\nb\nc");
	CHECK(st.pos == 0);
	CHECK(st.line == 1);
	CHECK(st.data[0] == 'a');
	UNIT_DONE();
}
