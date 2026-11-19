#include "harness.h"
#include "../../../../src/io.c"

int main(void){CHECK(file_exists(".")==1);CHECK(file_exists("no-such-path-xyz")==0);UNIT_DONE();}