# What is HookZz ?

**a cute hook framwork for arm/arm64/ios/android**

ref to: [frida-gum](https://github.com/frida/frida-gum) and [minhook](https://github.com/TsudaKageyu/minhook) and [substrate](https://github.com/jevinskie/substrate).

**special thanks to [frida-gum](https://github.com/frida/frida-gum) perfect code and modular architecture, frida is aircraft carrier, HookZz is boat, but still with some tricks**

**thanks to [capstone](https://github.com/aquynh/capstone), and the disassembly framework used is [Capstone](https://github.com/aquynh/capstone)**

# Features

- **inlinehook without Jailbreak [new]**

- **GOT hook with HookZz(i.e. change fishhook to inlinehook), better for APM [new]**

- [HookZz-Modules help you to hook.](https://github.com/jmpews/HookZzModules)

- the power to access registers directly

- hook function with `replace_call`

- hook function with `pre_call` and `post_call`

- hook **address(a piece of code)** with `pre_call` and `half_call`

- (almost)only **one instruction** to hook(i.e. hook **short funciton, even only one instruction**) [arm64]

- runtime code patch, without codesign limit

- it's cute

# Getting Started

[Move to HookZz Getting Started](https://jmpews.github.io/zzpp/getting-started/)

# How it works ?

[Move to HookFrameworkDesign.md](https://github.com/jmpews/HookZz/blob/master/docs/HookFrameworkDesign.md)

# Why I do this?

For Arsenal - [zzdeps](https://github.com/jmpews/zzdeps)

# Docs

[Move to HookZz docs](https://jmpews.github.io/zzpp/hookzz-docs/)

# Example

[Move to HookZz example](https://jmpews.github.io/zzpp/hookzz-example/)

# Modules

[Move to HookZzModules](https://github.com/jmpews/HookZzModules)

# Quick Example No.1

**Read It Carefully!**

```c
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

    // how to hook variadic function? fake a original copy stack.
    // [move to detail-1](http://jmpews.github.io/2017/08/29/pwn/%E7%9F%AD%E5%87%BD%E6%95%B0%E5%92%8C%E4%B8%8D%E5%AE%9A%E5%8F%82%E6%95%B0%E7%9A%84hook/)
    // [move to detail-2](https://github.com/jmpews/HookZzModules/tree/master/AntiDebugBypass)
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
```

breakpoint with lldb. **Read It Carefully!**

```
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

```

# Quick Example No.2

**Read It Carefully!**

```c
#include "hookzz.h"
#include <stdio.h>
#include <unistd.h>

static void hack_this_function()
{
#ifdef __arm64__
    __asm__("mov X0, #0\n"
            "mov w16, #20\n"
            "svc #0x80");
#endif
}

static void sorry_to_exit()
{
#ifdef __arm64__
    __asm__("mov X0, #0\n"
            "mov w16, #1\n"
            "svc #0x80");
#endif
}

void getpid_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    unsigned long request = *(unsigned long *)(&rs->general.regs.x16);
    printf("request(x16) is: %ld\n", request);
    printf("x0 is: %ld\n", (long)rs->general.regs.x0);
}

void getpid_half_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    pid_t x0 = (pid_t)(rs->general.regs.x0);
    printf("getpid() return at x0 is: %d\n", x0);
}

__attribute__((constructor)) void test_hook_address()
{
    void *hack_this_function_ptr = (void *)hack_this_function;
    ZzBuildHookAddress(hack_this_function_ptr + 8, hack_this_function_ptr + 12, getpid_pre_call, getpid_half_call);
    ZzEnableHook((void *)hack_this_function_ptr + 8);

    void *sorry_to_exit_ptr = (void *)sorry_to_exit;
    unsigned long nop_bytes = 0xD503201F;
    ZzRuntimeCodePatch((unsigned long)sorry_to_exit_ptr + 8, (zpointer)&nop_bytes, 4);

    hack_this_function();
    sorry_to_exit();

    printf("hack success -.0\n");
}
```

breakpoint with lldb. **Read It Carefully!**

```
(lldb) disass -n hack_this_function
test_hook_address.dylib`hack_this_function:
    0x1000b0280 <+0>:  mov    x0, #0x0
    0x1000b0284 <+4>:  mov    w16, #0x14
    0x1000b0288 <+8>:  svc    #0x80
    0x1000b028c <+12>: ret    

(lldb) disass -n sorry_to_exit
test_hook_address.dylib`sorry_to_exit:
    0x1000b0290 <+0>:  mov    x0, #0x0
    0x1000b0294 <+4>:  mov    w16, #0x1
    0x1000b0298 <+8>:  svc    #0x80
    0x1000b029c <+12>: ret    

(lldb) c
Process 41414 resuming
request(x16) is: 20
x0 is: 0
getpid() return at x0 is: 41414
hack success -.0
(lldb) disass -n hack_this_function
test_hook_address.dylib`hack_this_function:
    0x1000b0280 <+0>:  mov    x0, #0x0
    0x1000b0284 <+4>:  mov    w16, #0x14
    0x1000b0288 <+8>:  b      0x1001202cc
    0x1000b028c <+12>: ret    

(lldb) disass -n sorry_to_exit
test_hook_address.dylib`sorry_to_exit:
    0x1000b0290 <+0>:  mov    x0, #0x0
    0x1000b0294 <+4>:  mov    w16, #0x1
    0x1000b0298 <+8>:  nop    
    0x1000b029c <+12>: ret  
```

# Compile

## build for arm64-ios

```
jmpews at localhost in ~/Desktop/SpiderZz/project/HookZz (development●) (normal)
λ : >>> make -f ios.mk clean
clean all *.o success!
jmpews at localhost in ~/Desktop/SpiderZz/project/HookZz (development●) (normal)
λ : >>> make -f ios.mk BACKEND=ios ARCH=arm64

...ignore

build success for arm64-ios-hookzz!
```

check `build/ls build/ios-arm64`

#### build test for arm64(ios)

```
λ : >>> cd tests/arm64-ios
jmpews at localhost in ~/Desktop/SpiderZz/project/HookZz/tests/arm64-ios (development●) (normal)
λ : >>> make
build [test_hook_oc.dylib] success for arm64-ios!
build [test_hook_address.dylib] success for arm64-ios!
build [test_hook_printf.dylib] success for arm64-ios!
build [test] success for arm64-ios-hookzz!
```

## build for arm-android

```
jmpews at localhost in ~/Desktop/SpiderZz/project/HookZz (development●) (normal)
λ : >>> make -f ios.mk clean
clean all *.o success!
jmpews at localhost in ~/Desktop/SpiderZz/project/HookZz (development●) (normal)
λ : >>> make -f ios.mk BACKEND=ios ARCH=arm64

...ignore

build success for arm64-ios-hookzz!
```

check `build/ls build/ios-arm64`

#### build test for arm64(ios)

```
λ : >>> cd tests/arm64-ios
jmpews at localhost in ~/Desktop/SpiderZz/project/HookZz/tests/arm64-ios (development●) (normal)
λ : >>> make
build [test_hook_oc.dylib] success for arm64-ios!
build [test_hook_address.dylib] success for arm64-ios!
build [test_hook_printf.dylib] success for arm64-ios!
build [test] success for arm64-ios-hookzz!
```

