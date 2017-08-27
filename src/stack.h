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

#include "hookzz.h"

typedef struct _ZzCallStackItem {
    char *key;
    zpointer value;
} ZzCallStackItem;

typedef struct _ZzCallStack
{
    zpointer sp;
    zpointer caller_ret_addr;
	zsize size;
    zsize capacity;	
    ZzCallStackItem *items;
} ZzCallStack;

typedef struct _ZzStack
{
	zsize size;
    zsize capacity;
    zpointer key_ptr;
    ZzCallStack **callstacks;
} ZzStack;


ZzStack *ZzNewStack(zpointer key_ptr);
ZzStack *ZzGetCurrentThreadStack(zpointer key_ptr);

ZzCallStack *ZzNewCallStack();
ZzCallStack *ZzPopCallStack(ZzStack *stack);
bool ZzPushCallStack(ZzStack *stack, ZzCallStack *callstack);
    

#endif