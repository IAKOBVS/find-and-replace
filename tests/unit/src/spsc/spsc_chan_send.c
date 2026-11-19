#include "harness.h"
#include "../../../../src/spsc.c"

int main(void){spsc_chan_ty ch;void *slots[8];spsc_chan_init(&ch,slots,8);CHECK(spsc_chan_send(&ch,(void*)1)==0);CHECK(spsc_chan_recv(&ch)==(void*)1);spsc_chan_close(&ch);CHECK(spsc_chan_send(&ch,(void*)2)==-1);UNIT_DONE();}