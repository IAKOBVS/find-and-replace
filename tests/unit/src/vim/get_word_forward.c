#include "harness.h"
#include "../../../../src/vim.c"

int main(void){jstr_ty b=(jstr_ty)JSTR_INIT;CHECK(jstr_append_len_j(&b,"ab cd",5)==JSTR_RET_SUCC);CHECK(get_word_forward(&b,0)==3);CHECK(get_word_forward(&b,3)==5);jstr_free_j(&b);UNIT_DONE();}