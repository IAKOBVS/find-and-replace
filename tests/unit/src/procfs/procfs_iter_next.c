#include "harness.h"
#include "../../../../src/procfs.c"

int main(void){const char *s="MemAvailable: 123 kB\n";struct procfs_iter it;const char *k,*v;unsigned kl,vl;procfs_iter_init(&it,s,(unsigned)strlen(s));CHECK(procfs_iter_next(&it,&k,&kl,&v,&vl,'\n')==0);UNIT_DONE();}