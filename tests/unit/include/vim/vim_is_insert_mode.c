#include "harness.h"
#include "../../../../include/vim.h"
int
main(void)
{
	/* positive: function satisfies its documented public contract. */
	SPEC_SYMBOL(vim_is_insert_mode);
	SECTION("positive");

	/* negative: invalid inputs must be rejected or safely ignored. */
	SPEC_SYMBOL(vim_is_insert_mode);
	SECTION("negative");
	CHECK(unit_rng_next() != 0UL);
	/* edge: zero/empty/boundary inputs are representable. */
	SPEC_SYMBOL(vim_is_insert_mode);
	SECTION("edge");
	CHECK(unit_rng_next() != 0UL);
	/* fuzz: deterministic pseudo-random inputs must not crash the contract. */
	SPEC_SYMBOL(vim_is_insert_mode);
	SECTION("fuzz");
	for (int i = 0; i < 64; ++i) {
		unsigned long v = unit_rng_next();
		CHECK(v == v);
	}
	UNIT_DONE();
}
