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
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

int (*orig_printf)(const char * restrict format, ...);
int fake_printf(const char * restrict format, ...) {
    puts("call printf");

    char *stack[16];
    va_list args;
    va_start(args, format);
    memcpy(stack, args, 8 * 16);
    va_end(args);

    int x = orig_printf(format, stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7], stack[8], stack[9], stack[10], stack[11], stack[12], stack[13], stack[14], stack[15]);
    return x;
}

void printf_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    puts((char *)rs->general.regs.x0);
    STACK_SET(callstack, "format", rs->general.regs.x0, char *);
    puts("printf-pre-call");
}

void printf_post_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    if(STACK_CHECK_KEY(callstack, "format")) {
        char *format = STACK_GET(callstack, "format", char *);
        puts(format);
    }
    puts("printf-post-call");
}

__attribute__((constructor)) void test_hook_printf()
{
    void *printf_ptr = (void *)printf;

    ZzBuildHook((void *)printf_ptr, (void *)fake_printf, (void **)&orig_printf, printf_pre_call, printf_post_call);
    ZzEnableHook((void *)printf_ptr);
    printf("HookZzzzzzz, %d, %p, %d, %d, %d, %d, %d, %d, %d\n",1, (void *)2, 3, (char)4, (char)5, (char)6 , 7, 8 , 9);
}

/*

    Output:

    HookZzzzzzz, %d, %p, %d, %d, %d, %d, %d, %d, %d

    printf-pre-call
    call printf
    HookZzzzzzz, 1, 0x2, 3, 4, 5, 6, 7, 8, 9
    HookZzzzzzz, %d, %p, %d, %d, %d, %d, %d, %d, %d

    printf-post-call


*/