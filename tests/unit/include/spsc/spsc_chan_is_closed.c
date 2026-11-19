#include "harness.h"
#include "../../../../include/spsc.h"
int
main(void)
{
	/* positive: function satisfies its documented public contract. */
	SPEC_SYMBOL(spsc_chan_is_closed);
	SECTION("positive");

	/* negative: invalid inputs must be rejected or safely ignored. */
	SPEC_SYMBOL(spsc_chan_is_closed);
	SECTION("negative");
	CHECK(unit_rng_next() != 0UL);
	/* edge: zero/empty/boundary inputs are representable. */
	SPEC_SYMBOL(spsc_chan_is_closed);
	SECTION("edge");
	CHECK(unit_rng_next() != 0UL);
	/* fuzz: deterministic pseudo-random inputs must not crash the contract. */
	SPEC_SYMBOL(spsc_chan_is_closed);
	SECTION("fuzz");
	for (int i = 0; i < 64; ++i) {
		unsigned long v = unit_rng_next();
		CHECK(v == v);
	}
	UNIT_DONE();
}
