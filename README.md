# HookZz

> [Move to HookZz Getting Started](https://jmpews.github.io/zzpp/getting-started/)

> [Move to HookZz Example](https://jmpews.github.io/zzpp/hookzz-example/)

> [Move to HookZz docs](https://jmpews.github.io/zzpp/hookzz-docs/)

> [Move to HookZzModules](https://github.com/jmpews/HookZzModules)

> [Move to HookZzWebsite](https://jmpews.github.io/zzpp/)

# What is HookZz ?

**a cute hook framwork**. 

**still developing, for arm64/IOS now!**

ref to: [frida-gum](https://github.com/frida/frida-gum) and [minhook](https://github.com/TsudaKageyu/minhook) and [substrate](https://github.com/jevinskie/substrate).

**special thanks to `frida-gum's` perfect code and modular architecture, frida==aircraft carrier, hookzz==boat.**

# Features

- [HookZz-Modules help you to hook.](https://github.com/jmpews/HookZzModules)

- hook function with `replace_call`

- hook function with `pre_call` and `post_call`

- hook **address(a piece of code)** with `pre_call` and `half_call`

- almost only **one instruction** to hook(i.e.hook **short funciton, even only one instruction**)

- runtime code patch work with [MachoParser](https://github.com/jmpews/MachoParser),without codesign limit

- it's cute

# Getting Started

[Move to HookZz Getting Started](https://jmpews.github.io/zzpp/getting-started/)

# How it works ?

[Move to HookFrameworkDesign.md](https://github.com/jmpews/HookZz/blob/master/HookFrameworkDesign.md)

# Docs

[Move to HookZz docs](https://jmpews.github.io/zzpp/hookzz-docs/)

# Example

[Move to HookZz example](https://jmpews.github.io/zzpp/hookzz-example/)

# Quick Example

```
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
```

#### Instruction After Hook

```
libsystem_c.dylib`printf:
    0x1828eaa5c <+0>:  b      0x17a8eaa5c
    0x1828eaa60 <+4>:  stp    x29, x30, [sp, #0x10]
    0x1828eaa64 <+8>:  add    x29, sp, #0x10            ; =0x10 
    0x1828eaa68 <+12>: sub    sp, sp, #0x10             ; =0x10 
    0x1828eaa6c <+16>: mov    x19, x0
```

#### Output

```
HookZzzzzzz, %d, %p, %d, %d, %d, %d, %d, %d, %d

printf-pre-call
call printf
HookZzzzzzz, 1, 0x2, 3, 4, 5, 6, 7, 8, 9
HookZzzzzzz, %d, %p, %d, %d, %d, %d, %d, %d, %d

printf-post-call
```

# Compile

now only for `arm64/ios`.

#### build `libhookzz.static.a` and `libhookzz.dylib` for arm64(ios)

```
λ : >>> make -f darwin.ios.mk darwin.ios
generate [src/allocator.o]!
generate [src/interceptor.o]!
generate [src/memory.o]!
generate [src/stack.o]!
generate [src/thread.o]!
generate [src/trampoline.o]!
generate [src/platforms/posix/thread-posix.o]!
generate [src/platforms/darwin/memory-darwin.o]!
generate [src/platforms/arm64/reader.o]!
generate [src/platforms/arm64/relocator-arm64.o]!
generate [src/platforms/arm64/thunker-arm64.o]!
generate [src/platforms/arm64/writer-arm64.o]!
generate [src/zzdeps/darwin/macho-utils-darwin.o]!
generate [src/zzdeps/darwin/memory-utils-darwin.o]!
generate [src/zzdeps/common/memory-utils-common.o]!
generate [src/zzdeps/posix/memory-utils-posix.o]!
generate [src/zzdeps/posix/thread-utils-posix.o]!
build success for arm64(IOS)!
```

#### build test for arm64(ios)

```
λ : >>> make -f darwin.ios.mk test
build success for arm64(IOS)!
build [test_hook_oc.dylib] success for arm64(ios)!
build [test_hook_address.dylib] success for arm64(ios)!
build [test] success for arm64(IOS)!
```
