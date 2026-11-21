#include "harness.h"
#include "../../../../src/terminal.c"
int main(void)
{
	CHECK(field_affects_recompile(FIELD_FIND) == 1);
	CHECK(field_affects_recompile(FIELD_RPLC) == 0);
	CHECK(field_affects_recompile(FIELD_FLAGS) == 1);
	CHECK(field_affects_recompile(FIELD_COUNT) == 0);
	CHECK(field_affects_recompile(9999) == 0);
	UNIT_DONE();
}
