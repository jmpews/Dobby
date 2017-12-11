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

#ifndef interceptor_h
#define interceptor_h

#include "hookzz.h"
#include "kitzz.h"

#include "allocator.h"
#include "stack.h"
#include "thread.h"
#include "thunker.h"
#include "writer.h"

typedef struct _FunctionBackup {
    zz_ptr_t address;
    zz_size_t size;
    char data[32];
} FunctionBackup;

struct _ZzInterceptor;

/*
 * hook entry
 */

#define HOOK_FUNCTION_TYPE 1
#define HOOK_ADDRESS_TYPE 2

struct _ZzHookFunctionEntryBackend;
typedef struct _ZzHookFunctionEntry {
    int hook_type;
    unsigned long id;
    bool isEnabled;
    bool try_near_jump;

    zz_ptr_t thread_local_key;
    struct _ZzHookFunctionEntryBackend *backend;

    zz_ptr_t target_ptr;
    zz_ptr_t target_end_ptr;
    zz_ptr_t target_half_ret_addr;

    zz_ptr_t pre_call;
    zz_ptr_t half_call;
    zz_ptr_t post_call;
    zz_ptr_t replace_call;

    FunctionBackup origin_prologue;

    zz_ptr_t on_enter_transfer_trampoline;
    zz_ptr_t on_enter_trampoline;
    zz_ptr_t on_half_trampoline;
    zz_ptr_t on_invoke_trampoline;
    zz_ptr_t on_leave_trampoline;

    struct _ZzInterceptor *interceptor;
} ZzHookFunctionEntry;

typedef struct {
    ZzHookFunctionEntry **entries;
    zz_size_t size;
    zz_size_t capacity;
} ZzHookFunctionEntrySet;

struct _ZzInterceptorBackend;

typedef struct _ZzInterceptor {
    bool is_support_rx_page;
    ZzHookFunctionEntrySet hook_function_entry_set;
    struct _ZzInterceptorBackend *backend;
    ZzAllocator *allocator;
} ZzInterceptor;

#endif