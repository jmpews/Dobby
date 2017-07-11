//    Copyright 2017 jmpews
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

#ifndef interceptor_h
#define interceptor_h

#include "zz.h"
#include "../include/hookzz.h"
#include "allocator.h"

typedef struct _FunctionBackup
{
    zpointer address;
    uint8_t size;
    zbyte data[32];
} FunctionBackup;

struct _ZZInterceptor;

typedef struct _ZZHookEntry
{
    unsigned long id;
    uint8_t isEnabled;

    zpointer target_ptr;

    zpointer pre_call;
    zpointer post_call;
    zpointer replace_call;

    FunctionBackup old_prologue;

    zpointer on_enter_trampoline;
    zpointer on_invoke_trampoline;
    zpointer on_leave_trampoline;

    struct _ZZInterceptor *interceptor;
} ZZHookFunctionEntry;

typedef struct
{
    ZZHookFunctionEntry **entries;
    zuint size;
    zuint capacity;
} ZZHookFunctionEntrySet;

typedef struct _ZZInterceptorCenter
{
    ZZCodeSlice enter_thunk;
    ZZCodeSlice leave_thunk;
} ZZInterceptorCenter;

typedef struct _ZZInterceptor
{
    uint8_t isEnableCenterThunk;
    ZZHookFunctionEntrySet *func_entries;
    ZZInterceptorCenter *intercepter_center;
} ZZInterceptor;

ZZSTATUS ZZInitialize(void);
ZZHookFunctionEntry *ZZNewHookFunctionEntry(zpointer target);
ZZSTATUS ZZActiveEnterTrampoline(ZZHookFunctionEntry *entry);

#endif