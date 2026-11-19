#include "harness.h"
#include "../../../../src/ui.c"

int main(void){jstr_ty out=(jstr_ty)JSTR_INIT;CHECK(ui_format_grep_line(&out,"f",1,1,"abc",3,0,1)==JSTR_RET_SUCC);CHECK(out.size>0);jstr_free_j(&out);out=(jstr_ty)JSTR_INIT;CHECK(ui_format_grep_line(&out,"f",1,1,"abc",3,5,1)==JSTR_RET_ERR);jstr_free_j(&out);UNIT_DONE();}