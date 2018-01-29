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

#ifndef platforms_backend_arm64_intercetor_arm64
#define platforms_backend_arm64_intercetor_arm64

#include "hookzz.h"
#include "kitzz.h"

#include "platforms/arch-arm64/relocator-arm64.h"
#include "platforms/arch-arm64/writer-arm64.h"

#include "allocator.h"
#include "interceptor.h"
#include "thunker.h"
#include "tools.h"

#define CTX_SAVE_STACK_OFFSET (8 + 30 * 8 + 8 * 16)

typedef struct _ZzInterceptorBackend {
    ZzAllocator *allocator;
    ZzARM64Relocator arm64_relocator;

    ZzARM64AssemblerWriter arm64_writer;

    zz_ptr_t enter_thunk;
    zz_ptr_t half_thunk;
    zz_ptr_t leave_thunk;
} ZzInterceptorBackend;

typedef struct _ZzARM64HookFuntionEntryBackend {
    bool is_thumb;
    zz_size_t redirect_code_size;
} ZzARM64HookFunctionEntryBackend;

void ctx_save();
void ctx_restore();
void enter_thunk_template();
void leave_thunk_template();
void on_enter_trampoline_template();
void on_invoke_trampoline_template();
void on_leave_trampoline_template();

ZzCodeSlice *zz_arm64_code_patch(ZzARM64AssemblerWriter *arm64_writer, ZzAllocator *allocator, zz_addr_t target_addr,
                                 zz_size_t range_size);
#endif