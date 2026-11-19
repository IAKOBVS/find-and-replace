#include "harness.h"
#include "../../../../src/procfs.c"

int main(void){const char *s="MemAvailable: 123 kB\n";struct procfs_iter it;procfs_iter_init(&it,s,(unsigned)strlen(s));CHECK(it.pos!=NULL);UNIT_DONE();}