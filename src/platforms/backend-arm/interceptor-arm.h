/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#ifndef platforms_backend_arm_intercetor_arm
#define platforms_backend_arm_intercetor_arm

#include "hookzz.h"
#include "kitzz.h"

#include "allocator.h"
#include "interceptor.h"
#include "thunker.h"
#include "tools.h"

#include "platforms/arch-arm/relocator-arm.h"
#include "platforms/arch-arm/relocator-thumb.h"
#include "platforms/arch-arm/writer-arm.h"
#include "platforms/arch-arm/writer-thumb.h"

// (next_hop + general_regs + sp)
#define CTX_SAVE_STACK_OFFSET (4 * 14)

typedef struct _ZzInterceptorBackend {
    ZzAllocator *allocator;
    ZzArmRelocator arm_relocator;
    ZzThumbRelocator thumb_relocator;

    ZzArmWriter arm_writer;
    ZzThumbWriter thumb_writer;

    zz_ptr_t enter_thunk;
    zz_ptr_t half_thunk;
    zz_ptr_t leave_thunk;
} ZzInterceptorBackend;

typedef struct _ZzArmHookFuntionEntryBackend {
    bool is_thumb;
    zz_uint_t redirect_code_size;
} ZzArmHookFunctionEntryBackend;

ZzCodeSlice *zz_code_patch_thumb_writer(ZzThumbWriter *thumb_writer, ZzAllocator *allocator, zz_addr_t target_addr,
                                        zz_size_t range_size);

ZzCodeSlice *zz_code_patch_arm_writer(ZzArmWriter *arm_writer, ZzAllocator *allocator, zz_addr_t target_addr,
                                      zz_size_t range_size);

#endif