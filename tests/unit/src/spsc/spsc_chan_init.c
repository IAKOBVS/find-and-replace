#include "harness.h"
#include "../../../../src/spsc.c"

int main(void){spsc_chan_ty ch;void *slots[8];CHECK(spsc_chan_init(&ch,slots,8)==0);CHECK(spsc_chan_init(&ch,slots,3)==-1);CHECK(spsc_chan_init(&ch,NULL,8)==-1);UNIT_DONE();}