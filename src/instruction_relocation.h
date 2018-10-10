#include "interceptor.h"
#include "macros.h"

PLATFORM_API void instruction_relocation_inspect(void *dest, int *limit_length_PTR);

PLATFORM_API void instruction_relocation_build(void *dest, void *src, int length);