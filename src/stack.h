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
#include "kitzz.h"

#include "memory.h"
#include "thread.h"


typedef struct _ZzCallStackItem {
    char *key;
    zz_ptr_t value;
} ZzCallStackItem;

typedef struct _ZzCallStack {
    zz_size_t call_id;
    ThreadStack *threadstack;
    zz_size_t size;
    zz_size_t capacity;
    zz_ptr_t sp;
    zz_ptr_t caller_ret_addr;
    ZzCallStackItem *items;
} ZzCallStack;

typedef struct _ZzThreadStack {
    zz_size_t thread_id;
    zz_size_t size;
    zz_size_t capacity;
    zz_ptr_t key_ptr;
    ZzCallStack **callstacks;
} ZzThreadStack;

ZzThreadStack *ZzNewThreadStack(zz_ptr_t key_ptr);

ZzCallStack *ZzNewCallStack();

ZzThreadStack *ZzGetCurrentThreadStack(zz_ptr_t key_ptr);

bool ZzPushCallStack(ZzThreadStack *theadstack, ZzCallStack *callstack);

ZzCallStack *ZzPopCallStack(ZzThreadStack *stack);

void ZzFreeCallStack(ZzCallStack *callstack);

#endif