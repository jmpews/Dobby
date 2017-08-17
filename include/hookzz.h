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

#ifndef hook_zz_h
#define hook_zz_h

#include <stdint.h>
#include <stdbool.h>
#include "zzdefs.h"

typedef enum _ZZSTATUS {
    ZZ_UNKOWN = -1,
    ZZ_DONE = 0,
    ZZ_SUCCESS,
    ZZ_FAILED,
    ZZ_DONE_HOOK,
    ZZ_DONE_INIT,
    ZZ_DONE_ENABLE,
    ZZ_ALREADY_HOOK,
    ZZ_ALREADY_INIT,
    ZZ_ALREADY_ENABLED,
    ZZ_NEED_INIT,
    ZZ_NO_BUILD_HOOK
} ZZSTATUS;

typedef void *zpointer;
typedef unsigned long zsize;
typedef unsigned long zaddr;
typedef unsigned long zuint;
typedef long zint;
typedef unsigned char zbyte;

#define false 0
#define true 1

typedef struct _ZzCallerStack
{
	zpointer sp;
	zsize size;
    zsize capacity;	
	char **keys;
	zpointer *values;
} ZzCallerStack;

typedef void (*PRECALL)(RegState *rs, ZzCallerStack *stack);
typedef void (*POSTCALL)(RegState *rs, ZzCallerStack *stack);
typedef void (*HALFCALL)(RegState *rs, ZzCallerStack *stack);

zpointer ZzCallerStackGet(ZzCallerStack *stack , char *key);
ZZSTATUS ZzCallerStackSet(ZzCallerStack *stack, char *key, zpointer value_ptr, zsize value_size);

#define STACK_GET(stack, key, type) *(type *)ZzCallerStackGet(stack, key)
#define STACK_SET(stack, key, value, type) ZzCallerStackSet(stack, key, &value, sizeof(type))

ZZSTATUS ZzInitialize(void);
ZZSTATUS ZzBuildHook(zpointer target_ptr, zpointer replace_ptr, zpointer *origin_ptr, zpointer pre_call_ptr,
                     zpointer post_call_ptr);
ZZSTATUS ZzBuildHookAddress(zpointer target_start_ptr, zpointer target_end_ptr, zpointer pre_call_ptr, zpointer half_call_ptr);
ZZSTATUS ZzEnableHook(zpointer target_ptr);
ZZSTATUS ZzRuntimeCodePatch(zaddr address, zpointer codedata, zuint codedata_size);


#endif