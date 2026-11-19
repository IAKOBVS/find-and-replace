#include "harness.h"
#include "../../../../src/spsc.c"

int main(void){spsc_chan_ty ch;void *slots[2];spsc_chan_init(&ch,slots,2);CHECK(spsc_chan_try_recv(&ch)==NULL);CHECK(spsc_chan_send(&ch,(void*)9)==0);CHECK(spsc_chan_try_recv(&ch)==(void*)9);UNIT_DONE();}