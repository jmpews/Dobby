
#ifndef platforms_backend_arm_intercetor_arm
#define platforms_backend_arm_intercetor_arm

#include "hookzz.h"

#include "interceptor.h"
#include "allocator.h"

#include "platforms/arch/arm/writer-arm.h"
#include "platforms/arch/arm/writer-thumb.h"
#include "platforms/arch/arm/relocator-arm.h"
#include "platforms/arch/arm/relocator-thumb.h"


typedef struct _ZzArmInterceptorBackend
{
    ZzAllocator *allocator;
    ZzArmRelocator arm_relocator;
    ZzThumbRelocator thumb_relocator;

    ZzArmWriter arm_writer;
    ZzThumbWriter arm_writer;

    zpinter enter_thunk;
    zpointer leave_thunk;
} _ZzInterceptorBackend;

typedef struct _ZzArmHookFuntionEntryBackend
{
    zbool is_thumb;
    zuint redirect_code_size;
} ZzArmHookFunctionEntryBackend;

#endif