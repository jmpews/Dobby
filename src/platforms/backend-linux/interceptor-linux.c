#include <stdlib.h>
#include <string.h>

#include "interceptor-linux.h"
#include "interceptor.h"
#include "trampoline.h"

RetStatus ZzHookGOT(const char *name, zz_ptr_t replace_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
                   POSTCALL post_call_ptr) {

    return RS_SUCCESS;
}

RetStatus ZzDisableHookGOT(const char *name) { return RS_SUCCESS; }