
#ifndef platforms_backend_arm_intercetor_arm
#define platforms_backend_arm_intercetor_arm

// platforms
#include "platforms/arch-arm/relocator-arm.h"
#include "platforms/arch-arm/relocator-thumb.h"
#include "platforms/arch-arm/writer-arm.h"
#include "platforms/arch-arm/writer-thumb.h"

// hookzz
#include "allocator.h"
#include "interceptor.h"

// zzdeps
#include "hookzz.h"
#include "zzdefs.h"
#include "zzdeps/common/debugbreak.h"
#include "zzdeps/zz.h"

typedef struct _ZzInterceptorBackend {
    ZzAllocator *allocator;
    ZzArmRelocator arm_relocator;
    ZzThumbRelocator thumb_relocator;

    ZzArmWriter arm_writer;
    ZzThumbWriter thumb_writer;

    zpointer enter_thunk;
    zpointer leave_thunk;
} ZzInterceptorBackend;

typedef struct _ZzArmHookFuntionEntryBackend {
    zbool is_thumb;
    zuint redirect_code_size;
} ZzArmHookFunctionEntryBackend;

#endif