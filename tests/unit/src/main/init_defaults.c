#include "harness.h"
#define main far_main_disabled
#include "../../../../src/main.c"
#undef main
int main(void)
{
	G.cflags = 123;
	G.n = 99;
	G.eflags = 7;
	init_defaults();
	CHECK(G.cflags == JSTR_RE_CF_NEWLINE);
	CHECK(G.n == 1);
	CHECK(G.eflags == 0);
	G.cflags = 456;
	G.n = 42;
	G.eflags = 9;
	init_defaults();
	CHECK(G.cflags == JSTR_RE_CF_NEWLINE);
	CHECK(G.n == 1);
	CHECK(G.eflags == 0);
	UNIT_DONE();
}
