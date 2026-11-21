#include "harness.h"
#include "../../../../src/terminal.c"
int main(void)
{
	CHECK(grep_field_affects_recompile(GREP_FIELD_FIND) == 1);
	CHECK(grep_field_affects_recompile(GREP_FIELD_FILES) == 1);
	CHECK(grep_field_affects_recompile(GREP_FIELD_INCLUDE) == 1);
	CHECK(grep_field_affects_recompile(GREP_FIELD_EXCLUDE) == 1);
	CHECK(grep_field_affects_recompile(GREP_FIELD_COUNT) == 0);
	UNIT_DONE();
}
