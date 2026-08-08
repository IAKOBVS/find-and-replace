#include <stdio.h>
#include <jstr/jstr.h>
#include <jstr/regex.h>

int main() {
    jstr_re_ty preg;
    jstr_re_comp(&preg, "\\w?", REG_EXTENDED | REG_NEWLINE);
    jstr_ty s = JSTR_INIT;
    jstr_assign_len(jstr_struct(&s), "u", 1);
    regoff_t ret = jstr_re_rplcn_backref_len_exec_j(&preg, &s, "d", 1, 0, 10, (size_t)-1);
    printf("ret=%ld, s.size=%zu, s.data='%s'\n", (long)ret, s.size, s.data);
    jstr_re_free(&preg);
    jstr_free_j(&s);
    return 0;
}
