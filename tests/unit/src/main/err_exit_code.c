#include "harness.h"
#define main far_main_disabled
#include "../../../../src/main.c"
#undef main
int main(void)
{
	G.mode = 0;
	CHECK(err_exit_code() == EXIT_FAILURE);
	G.mode = MODE_GREP;
	CHECK(err_exit_code() == 2);
	G.mode = MODE_GREP | MODE_PRINT_CHANGES;
	CHECK(err_exit_code() == 2);
	UNIT_DONE();
}
