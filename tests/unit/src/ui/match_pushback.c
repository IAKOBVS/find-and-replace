#include "harness.h"
#include "../../../../src/ui.c"
int
main(void)
{
	SPEC_SYMBOL(match_pushback);
	SECTION("positive");
	matches_ty m = {0};
	match_pushback(&m, 1, 2, NULL);
	CHECK(m.size == 1);
	CHECK(m.cap >= 1);
	CHECK(m.data != NULL);
	CHECK(m.data[0].start == 1);
	CHECK(m.data[0].end == 2);
	CHECK(m.data[0].rm[0].rm_so == 0);
	SECTION("negative");
	CHECK(matches_reserve(&m, 0) == JSTR_RET_SUCC);
	CHECK(m.size == 1);
	CHECK(m.data[0].end == 2);
	SECTION("edge");
	regmatch_t rm[JSTR_NMATCH_MAX];
	memset(rm, 0, sizeof(rm));
	rm[0].rm_so = 3;
	rm[0].rm_eo = 7;
	match_pushback(&m, 8, 12, rm);
	CHECK(m.size == 2);
	CHECK(m.data[1].start == 8);
	CHECK(m.data[1].end == 12);
	CHECK(m.data[1].rm[0].rm_so == 3);
	CHECK(m.data[1].rm[0].rm_eo == 7);
	SECTION("fuzz");
	CHECK(matches_reserve(&m, 64) == JSTR_RET_SUCC);
	for (int i = 0; i < 64; ++i) {
		unsigned long v = unit_rng_next();
		size_t start = (size_t)(v % 97);
		match_pushback(&m, start, start + 1, NULL);
	}
	CHECK(m.size == 66);
	CHECK(m.cap >= m.size);
	free(m.data);
	UNIT_DONE();
}
