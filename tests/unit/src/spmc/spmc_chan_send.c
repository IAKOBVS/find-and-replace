#include "harness.h"
#include "../../../../src/spmc.c"

int main(void){spmc_slot_ty slots[8];spmc_chan_ty ch;spmc_chan_init(&ch,slots,8);CHECK(spmc_chan_send(&ch,(void*)5)==0);CHECK(spmc_chan_try_recv(&ch)==(void*)5);UNIT_DONE();}