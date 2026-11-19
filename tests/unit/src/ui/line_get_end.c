#include "harness.h"
#include "../../../../src/ui.c"

int main(void){const char *s="ab\ncd";CHECK(line_get_end(s,5,0)==2);CHECK(line_get_end(s,5,3)==5);UNIT_DONE();}