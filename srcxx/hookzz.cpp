#include "hookzz_internal.h"

#include "Interceptor.h"

RetStatus ZzHook(void *address, void *replace_call, void **origin_call, PRECALL pre_call, POSTCALL post_call) {
  return RS_DONE;
}