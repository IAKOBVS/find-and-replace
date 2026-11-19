#include "harness.h"
#include "../../../../src/spsc.c"

int main(void){spsc_chan_ty *c=spsc_chan_new(0);CHECK(c!=NULL);spsc_chan_free(c);CHECK(spsc_chan_new((size_t)-1)==NULL);UNIT_DONE();}