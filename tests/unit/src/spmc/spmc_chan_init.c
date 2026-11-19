#include "harness.h"
#include "../../../../src/spmc.c"

int main(void){spmc_slot_ty slots[8];spmc_chan_ty ch;CHECK(spmc_chan_init(&ch,slots,8)==0);CHECK(spmc_chan_init(&ch,slots,3)==-1);UNIT_DONE();}