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

#include "hookzz.h"
#include <stdio.h>
static void hack_this_function()
{
#ifdef __arm64__
    __asm__("mov X0, #0\n"
            "mov w16, #20\n"
            "svc #0x80\n"
            "mov x9, #1\n"
            "mov x9, #2\n"
            "mov x9, #3\n"
            "mov x9, #4\n"
            "mov x9, #5\n"
            "mov x9, #6\n"
            "mov x9, #7");
#endif
}

void hook_pre_call(struct RegState_ *rs, ZzCallerStack *stack)
{
    unsigned long request = *(unsigned long *)(&rs->general.regs.x16);
    printf("request is: %ld\n", request);
}

void hook_half_call(struct RegState_ *rs, ZzCallerStack *stack)
{
    unsigned long x0 = (unsigned long)(rs->general.regs.x0);
    printf("getpid() return %ld\n", x0);
}

__attribute__((constructor)) void test_hook_address()
{
    ZzInitialize();
    void *hack_this_function_ptr = (void *)hack_this_function;
    // hook address with only `pre_call`
    ZzBuildHookAddress(hack_this_function_ptr + 8, hack_this_function_ptr + 12, (void *)hook_pre_call, NULL);

    // hook address with only `half_call`
    // ZzBuildHookAddress(hack_this_function_ptr + 8, hack_this_function_ptr + 12, NULL, (void *)hook_half_call);

    // hook address with both `half_call` and `pre_call`
    // ZzBuildHookAddress(hack_this_function_ptr + 8, hack_this_function_ptr + 12, (void *)hook_pre_call, (void *)hook_half_call);
    ZzEnableHook((void *)hack_this_function_ptr + 8);

    hack_this_function();

    printf("hack success -.0\n");
}
