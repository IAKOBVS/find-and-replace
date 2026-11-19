#include "harness.h"
#include "../../../../src/procfs.c"

int main(void){size_t v=procfs_mem_available();CHECK(v>0);UNIT_DONE();}