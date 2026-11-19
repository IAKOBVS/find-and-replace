#include "harness.h"
#include "../../../../src/io.c"

int main(void){struct stat st;CHECK(xstat(".",&st)==JSTR_RET_SUCC);CHECK(xstat("no-such-path-xyz",&st)==JSTR_RET_ERR);UNIT_DONE();}