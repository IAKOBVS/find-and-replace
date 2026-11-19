#include "harness.h"
#include "../../../../src/ui.c"

int main(void){const char *s="ab\ncd";CHECK(line_get_start(s,5,0)==0);CHECK(line_get_start(s,5,3)==3);UNIT_DONE();}