#include "harness.h"
#include "../../../../src/vim.c"
#include <string.h>

int main(void){jstr_ty b=(jstr_ty)JSTR_INIT;CHECK(jstr_append_len_j(&b,"abcdef",6)==JSTR_RET_SUCC);delete_range(&b,1,3);CHECK(strcmp(b.data,"adef")==0);jstr_free_j(&b);UNIT_DONE();}