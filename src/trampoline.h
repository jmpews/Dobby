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

#ifndef trampoline_h
#define trampoline_h

#include "hookzz.h"
#include "kitzz.h"

#include "interceptor.h"

typedef struct _ZzTrampoline {
    ZzCodeSlice *code_slice;
} ZzTrampoline;

struct _ZzInterceptorBackend *ZzBuildInteceptorBackend(ZzAllocator *allocator);

ZzHookFunctionEntry *ZzFindHookFunctionEntry(zz_ptr_t target_ptr);

ZZSTATUS ZzFreeTrampoline(ZzHookFunctionEntry *entry);

ZZSTATUS ZzPrepareTrampoline(struct _ZzInterceptorBackend *self, ZzHookFunctionEntry *entry);

ZZSTATUS ZzBuildTrampoline(struct _ZzInterceptorBackend *self, ZzHookFunctionEntry *entry);

ZZSTATUS ZzActivateTrampoline(struct _ZzInterceptorBackend *self, ZzHookFunctionEntry *entry);

ZZSTATUS ZzBuildEnterTrampoline(struct _ZzInterceptorBackend *self, ZzHookFunctionEntry *entry);

ZZSTATUS ZzBuildEnterTransferTrampoline(struct _ZzInterceptorBackend *self, ZzHookFunctionEntry *entry);

ZZSTATUS ZzBuildHalfTrampoline(struct _ZzInterceptorBackend *self, ZzHookFunctionEntry *entry);

ZZSTATUS ZzBuildInvokeTrampoline(struct _ZzInterceptorBackend *self, ZzHookFunctionEntry *entry);

ZZSTATUS ZzBuildLeaveTrampoline(struct _ZzInterceptorBackend *self, ZzHookFunctionEntry *entry);

#ifdef TARGET_IS_IOS
// ZZSTATUS ZzActivateSolidifyTrampoline(ZzHookFunctionEntry *entry, zz_addr_t target_fileoff);
#endif

#endif