#include "harness.h"
#include "../../../../src/ui.c"
int
main(void)
{
	SPEC_SYMBOL(matches_reserve);
	SECTION("positive");
	matches_ty m = {0};
	CHECK(matches_reserve(&m, 52) == JSTR_RET_SUCC);
	CHECK(m.cap >= 52);
	CHECK(m.size == 0);
	CHECK(m.data != NULL);
	SECTION("negative");
	m.cap = 0;
	m.size = 0;
	free(m.data);
	m.data = NULL;
	CHECK(matches_reserve(&m, 0) == JSTR_RET_SUCC);
	CHECK(m.cap == 0);
	CHECK(m.data == NULL);
	SECTION("edge");
	CHECK(matches_reserve(&m, 1) == JSTR_RET_SUCC);
	CHECK(m.cap >= 1);
	CHECK(matches_reserve(&m, m.cap) == JSTR_RET_SUCC);
	CHECK(m.cap >= 1);
	SECTION("fuzz");
	for (int i = 0; i < 64; ++i) {
		unsigned long v = unit_rng_next();
		CHECK(matches_reserve(&m, (size_t)(v % 97)) == JSTR_RET_SUCC);
		CHECK(m.cap >= v % 97);
	}
	free(m.data);
	UNIT_DONE();
}
