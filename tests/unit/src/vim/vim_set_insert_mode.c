#include "harness.h"
#include "../../../../src/vim.c"

int main(void){vim_set_insert_mode(1);CHECK(vim_is_insert_mode()==1);vim_set_insert_mode(0);CHECK(vim_is_insert_mode()==0);UNIT_DONE();}