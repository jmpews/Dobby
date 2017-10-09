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
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int (*orig_printf)(const char *restrict format, ...);
int fake_printf(const char *restrict format, ...) {
    puts("call printf");

    char *stack[16];
    va_list args;
    va_start(args, format);
    memcpy(stack, args, 8 * 16);
    va_end(args);

    // how to hook variadic function? fake a original copy stack.
    // [move to
    // detail-1](http://jmpews.github.io/2017/08/29/pwn/%E7%9F%AD%E5%87%BD%E6%95%B0%E5%92%8C%E4%B8%8D%E5%AE%9A%E5%8F%82%E6%95%B0%E7%9A%84hook/)
    // [move to detail-2](https://github.com/jmpews/HookZzModules/tree/master/AntiDebugBypass)
    int x = orig_printf(format, stack[0], stack[1], stack[2], stack[3], stack[4], stack[5],
                        stack[6], stack[7], stack[8], stack[9], stack[10], stack[11], stack[12],
                        stack[13], stack[14], stack[15]);
    return x;
}

void printf_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    puts((char *)rs->general.regs.x0);
    STACK_SET(callstack, "format", rs->general.regs.x0, char *);
    puts("printf-pre-call");
}

void printf_post_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    if (STACK_CHECK_KEY(callstack, "format")) {
        char *format = STACK_GET(callstack, "format", char *);
        puts(format);
    }
    puts("printf-post-call");
}

__attribute__((constructor)) void test_hook_printf() {
    void *printf_ptr = (void *)printf;

    ZzBuildHook((void *)printf_ptr, (void *)fake_printf, (void **)&orig_printf, printf_pre_call,
                printf_post_call);
    ZzEnableHook((void *)printf_ptr);
    printf("HookZzzzzzz, %d, %p, %d, %d, %d, %d, %d, %d, %d\n", 1, (void *)2, 3, (char)4, (char)5,
           (char)6, 7, 8, 9);
}

/*

(lldb) disass -s 0x1815f61d8 -c 3
libsystem_c.dylib`printf:
    0x1815f61d8 <+0>: sub    sp, sp, #0x30             ; =0x30
    0x1815f61dc <+4>: stp    x20, x19, [sp, #0x10]
    0x1815f61e0 <+8>: stp    x29, x30, [sp, #0x20]
(lldb) c
Process 41408 resuming
HookZzzzzzz, %d, %p, %d, %d, %d, %d, %d, %d, %d

printf-pre-call
call printf
HookZzzzzzz, 1, 0x2, 3, 4, 5, 6, 7, 8, 9
HookZzzzzzz, %d, %p, %d, %d, %d, %d, %d, %d, %d

printf-post-call
(lldb) disass -s 0x1815f61d8 -c 3
libsystem_c.dylib`printf:
    0x1815f61d8 <+0>: b      0x1795f61d8
    0x1815f61dc <+4>: stp    x20, x19, [sp, #0x10]
    0x1815f61e0 <+8>: stp    x29, x30, [sp, #0x20]


*/