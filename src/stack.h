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

#ifndef stack_h
#define stack_h

#include "../include/zz.h"
#include "../include/hookzz.h"

typedef struct _ZzStack
{
	zsize size;
    zsize capacity;
    ZzCallerStack **caller_stacks;
    zpointer thread_local_key_ptr;
} ZzStack;


void ZzInitializeThreadLocalKey();
zpointer ZzNewThreadLocalKey();
ZzStack *ZzCurrentThreadStack(zpointer thread_local_key_ptr);
ZzStack * ZzNewStack(zpointer thread_local_key_ptr);
ZzCallerStack *ZzNewCallerStack();
ZzCallerStack *ZzStackPOP(ZzStack *stack);
ZZSTATUS ZzStackPUSH(ZzStack *stack, ZzCallerStack *caller_stack);

#endif