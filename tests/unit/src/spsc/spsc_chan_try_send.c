#include "harness.h"
#include "../../../../src/spsc.c"

int main(void){spsc_chan_ty ch;void *slots[2];spsc_chan_init(&ch,slots,2);CHECK(spsc_chan_try_send(&ch,(void*)1)==0);CHECK(spsc_chan_try_send(&ch,(void*)2)==0);CHECK(spsc_chan_try_send(&ch,(void*)3)==-1);CHECK(spsc_chan_try_recv(&ch)==(void*)1);CHECK(spsc_chan_try_send(&ch,(void*)3)==0);UNIT_DONE();}