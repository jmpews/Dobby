
#ifndef platforms_backend_arm64_intercetor_arm64
#define platforms_backend_arm64_intercetor_arm64

// platforms
#include "platforms/arch-arm64/relocator-arm64.h"
#include "platforms/arch-arm64/writer-arm64.h"

// hookzz
#include "allocator.h"
#include "interceptor.h"
#include "thunker.h"

// zzdeps
#include "hookzz.h"
#include "zzdefs.h"
#include "zzdeps/common/debugbreak.h"
#include "zzdeps/zz.h"

#define CTX_SAVE_STACK_OFFSET (8 + 30 * 8 + 8 * 16)

typedef struct _ZzInterceptorBackend {
    ZzAllocator *allocator;
    ZzArm64Relocator arm64_relocator;

    ZzArm64Writer arm64_writer;

    zpointer enter_thunk;
    zpointer half_thunk;
    zpointer leave_thunk;
} ZzInterceptorBackend;

typedef struct _ZzArm64HookFuntionEntryBackend {
    zbool is_thumb;
    zuint redirect_code_size;
} ZzArm64HookFunctionEntryBackend;

#endif