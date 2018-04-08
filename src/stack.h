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

#ifndef stack_h
#define stack_h

#include "hookzz.h"
#include "zkit.h"

#include "memhelper.h"
#include "thread.h"

typedef struct _CallStackEntry {
    char *key;
    zz_ptr_t value;
} CallStackEntry;

struct _ThreadStack;

typedef struct _CallStack {
    zz_size_t call_id;
    struct _ThreadStack *threadstack;
    zz_size_t size;
    zz_size_t capacity;
    zz_ptr_t reg_sp;
    zz_ptr_t retAddr;
    CallStackEntry *callstack_entry_list;
} CallStack;

typedef struct _ThreadStack {
    zz_size_t thread_id;
    zz_size_t size;
    zz_size_t capacity;
    zz_ptr_t thread_local_key;
    CallStack **callstack_ptr_list;
} ThreadStack;

ThreadStack *ThreadStackAllocate(zz_ptr_t thread_local_key);

CallStack *CallStackAllocate();

ThreadStack *ThreadStackGetByThreadLocalKey(zz_ptr_t thread_local_key);

bool ThreadStackPushCallStack(ThreadStack *theadstack, CallStack *callstack);

CallStack *ThreadStackPopCallStack(ThreadStack *stack);

void CallStackFree(CallStack *callstack);

#endif