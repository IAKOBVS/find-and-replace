#include "harness.h"
#include "../../../../src/ui.c"

int main(void){CHECK(ui_size_t_width(0)==1);CHECK(ui_size_t_width(9)==1);CHECK(ui_size_t_width(10)==2);CHECK(ui_size_t_width(12345)==5);UNIT_DONE();}