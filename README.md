## HookZz

> [Move to HookZz Getting Started](https://jmpews.github.io/zzpp/getting-started/)

> [Move to HookZzModules](https://github.com/jmpews/HookZzModules)

> [Move to HookZzWebsite](https://jmpews.github.io/zzpp/)

## What is HookZz?

**a cute hook framwork**. 

**still developing, for arm64/IOS now!**

ref to: [frida-gum](https://github.com/frida/frida-gum) and [minhook](https://github.com/TsudaKageyu/minhook) and [substrate](https://github.com/jevinskie/substrate).

**special thanks to `frida-gum's` perfect code and modular architecture.**


## How it works ?

[Move to HookFrameworkDesign.md](https://github.com/jmpews/HookZz/blob/master/HookFrameworkDesign.md)

## How use it ?

**export 5 func**:

```
// initialize the interceptor and so on.
ZzSTATUS ZzInitialize(void);

// build hook with `replace_call`, `pre_call`, `post_call`, but not enable.
ZzSTATUS ZzBuildHook(zpointer target_ptr, zpointer replace_ptr, zpointer *origin_ptr, zpointer pre_call_ptr, zpointer post_call_ptr);

// build hook address with `pre_call`, `half_call`
ZZSTATUS ZzBuildHookAddress(zpointer target_start_ptr, zpointer target_end_ptr, zpointer pre_call_ptr, zpointer half_call_ptr);

// enable hook, with `code patch`
ZzSTATUS ZzEnableHook(zpointer target_ptr);

// runtime code patch
ZZSTATUS ZzRuntimeCodePatch(zaddr address, zpointer codedata, zuint codedata_size);
```

**export 1 variable**:

```
// current all cpu register state, read `zzdefs.h` for detail.
#if defined (__aarch64__)
typedef union FPReg_ {
    __int128_t q;
    struct {
        double d1; // Holds the double (LSB).
        double d2;
    } d;
    struct {
        float f1; // Holds the float (LSB).
        float f2;
        float f3;
        float f4;
    } f;
} FPReg;

// just ref how to backup/restore registers
struct RegState_ {
    uint64_t pc;
    uint64_t sp;

    union {
        uint64_t x[29];
        struct {
            uint64_t x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28;
        } regs;
    } general;

    uint64_t fp;
    uint64_t lr;

    union {
        FPReg q[8];
        FPReg q0,q1,q2,q3,q4,q5,q6,q7;
    } floating;
};
```

and the `pre_call`, `post_call` and `half_call` type is blow.

```
typedef void (*PRECALL)(struct RegState_ *rs);
typedef void (*POSTCALL)(struct RegState_ *rs);
typedef void (*HALFCALL)(struct RegState_ *rs);
```

## Simple Example

#### 1.use `ZzBuildHookAddress`

hook at address, and specify the hook length. (i.e. hook a piece of code.)

```
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

void hook_pre_call(struct RegState_ *rs)
{
    unsigned long request = *(unsigned long *)(&rs->general.regs.x16);
    printf("request is: %ld\n", request);
}

void hook_half_call(struct RegState_ *rs)
{
    unsigned long x0 = (unsigned long)(rs->general.regs.x0);
    printf("getpid() return %ld\n", x0);
}

__attribute__((constructor)) void test_hook_address()
{
    ZzInitialize();
    void *hack_this_function_ptr = (void *)hack_this_function;
    // hook address with only `pre_call`
    // ZzBuildHookAddress(hack_this_function_ptr + 8, 0, (void *)hook_pre_call, NULL);

    // hook address with only `half_call`
    // ZzBuildHookAddress(hack_this_function_ptr + 8, hack_this_function_ptr + 12, NULL, (void *)hook_half_call);

    // hook address with both `half_call` and `pre_call`
    ZzBuildHookAddress(hack_this_function_ptr + 8, hack_this_function_ptr + 12, (void *)hook_pre_call, (void *)hook_half_call);
    ZzEnableHook((void *)hack_this_function_ptr + 8);

    hack_this_function();

    printf("hack success -.0\n");
}
```

**hook address with only `pre_call` output:**

```
request is: 20
hack success -.0
```

**hook address with only `half_call` output:**

```
getpid() return 27672
hack success -.0
```

**hook address with both `half_call` and `pre_call` output:**

```
request is: 20
getpid() return 27675
hack success -.0
```

#### 2.use `ZzBuildHook`

```
#include "hookzz.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

@interface HookZz : NSObject

@end

@implementation HookZz

+ (void)load {
    [self zzMethodSwizzlingHook];
}

void objcMethod_pre_call(struct RegState_ *rs) {
  NSLog(@"hookzz OC-Method: -[ViewController %s]",
        (zpointer)(rs->general.regs.x1));
}

+ (void)zzMethodSwizzlingHook {
    Class hookClass = objc_getClass("UIViewController");
    SEL oriSEL = @selector(viewWillAppear:);
    Method oriMethod = class_getInstanceMethod(hookClass, oriSEL);
    IMP oriImp = method_getImplementation(oriMethod);

    ZzInitialize();
    ZzBuildHook((void *)oriImp, NULL, NULL, (zpointer)objcMethod_pre_call, NULL);
    ZzEnableHook((void *)oriImp);
}

@end
```

**hook oc method output:**

```
2017-08-16 02:53:48.237242+0800 T007[27678:6820897] hookzz OC-Method: -[ViewController viewWillAppear:]
```

#### 3.use `ZzRuntimeCodePatch`

`ZzRuntimeCodePatch` usually works with [MachoParser](https://github.com/jmpews/MachoParser)

```
__attribute__((constructor)) void patch_svc_x80() {
  const section_64_info_t *sect64;
  zaddr svc_x80_addr;
  zaddr curr_addr, end_addr;
  uint32_t svc_x80_byte = 0xd4001001;
  MachoMem *mem = new MachoMem();
  mem->parse_macho();
  // mem->parse_dyld();
  sect64 = mem->get_sect_by_name("__text");
  curr_addr = sect64->sect_addr;
  end_addr = curr_addr + sect64->sect_64->size;

  ZzInitialize();
  while (curr_addr < end_addr) {
    svc_x80_addr = mem->macho_search_data(
        sect64->sect_addr, sect64->sect_addr + sect64->sect_64->size,
        (const zbyte *)&svc_x80_byte, 4);
    if (svc_x80_addr) {
      NSLog(@"patch svc #0x80 with 'nop' at %p with aslr (%p without aslr)",
            (void *)svc_x80_addr, (void *)(svc_x80_addr - mem->m_aslr_slide));
      unsigned long nop_bytes = 0xD503201F;
      ZzRuntimeCodePatch(svc_x80_addr, (zpointer)&nop_bytes, 4);
      curr_addr = svc_x80_addr + 4;
    } else {
      break;
    }
  }
}
```

## Advanced Example

#### use `replace_call` bypass syscall-antidebug

```
// ptrace(int request, pid_t pid, caddr_t addr, int data);
int (*orig_syscall)(int number, ...);
int fake_syscall(int number, ...) {
  int request;
  pid_t pid;
  caddr_t addr;
  int data;

  // fake stack, why use `char *` ? hah
  char *stack[8];

  va_list args;
  va_start(args, number);

  // get the origin stack args copy.(must >= origin stack args)
  memcpy(stack, args, 8 * 8);

  if (number == SYS_ptrace) {
    request = va_arg(args, int);
    pid = va_arg(args, pid_t);
    addr = va_arg(args, caddr_t);
    data = va_arg(args, int);
    va_end(args);
    if (request == PT_DENY_ATTACH) {
      NSLog(@"[AntiDebugBypass] catch 'syscall(SYS_ptrace, PT_DENY_ATTACH, 0, "
            @"0, 0)' and bypass.");
      return 0;
    }
  } else {
    va_end(args);
  }

  // must understand the principle of `function call`. `parameter pass` is before `switch to target`
  // so, pass the whole `stack`, it just actually faked an original stack.
  // Not pass a large structure,  will be replace with a `hidden memcpy`.
  int x = orig_syscall(number, stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7]);
  return x;
}

__attribute__((constructor)) void patch_ptrace_sysctl_syscall() {

  ...

  zpointer syscall_ptr = (void *)syscall;
  ZzBuildHook((void *)syscall_ptr, (void *)fake_syscall, (void
  **)&orig_syscall,
              NULL, NULL);
  ZzEnableHook((void *)syscall_ptr);
}
// --- end --
```

#### use `pre_call` bypass syscall-antidebug

```
// --- syscall bypass use `pre_call`
void syscall_pre_call(struct RegState_ *rs) {
  int num_syscall;
  int request;
  zpointer sp;
  num_syscall = (int)(uint64_t)(rs->general.regs.x0);
  if (num_syscall == SYS_ptrace) {
    sp = (zpointer)(rs->sp);
    request = *(int *)sp;
    if (request == PT_DENY_ATTACH) {
      *(long *)sp = 10;
      NSLog(@"[AntiDebugBypass] catch 'syscall(SYS_ptrace, PT_DENY_ATTACH, 0, "
            @"0, 0)' and bypass.");
    }
  }
}
__attribute__((constructor)) void patch_syscall_by_pre_call() {
  zpointer syscall_ptr = (void *)syscall;
  ZzBuildHook((void *)syscall_ptr, NULL, NULL, (void *)syscall_pre_call, NULL);
  ZzEnableHook((void *)syscall_ptr);
}

// --- end ---
```

#### hook Objective-C method.

read `<objc/runtime.h>` funciton.

```
+ (void)load
{
    [self zzMethodSwizzlingHook];
}

void objcMethod_pre_call(struct RegState_ *rs) {
  NSLog(@"hookzz OC-Method: -[ViewController %s]",
        (zpointer)(rs->general.regs.x1));
}

+ (void)zzMethodSwizzlingHook {
  Class hookClass = objc_getClass("UIViewController");
  SEL oriSEL = @selector(viewWillAppear:);
  Method oriMethod = class_getInstanceMethod(hookClass, oriSEL);
  IMP oriImp = method_getImplementation(oriMethod);

  ZzInitialize();
  ZzBuildHook((void *)oriImp, NULL, NULL, (zpointer)objcMethod_pre_call, NULL);
  ZzEnableHook((void *)oriImp);
}
```

## Compile

now only for `arm64/ios`.

#### for arm64 & ios

```
λ : >>> make -f darwin.ios.mk darwin.ios
generate [src/allocator.o]!
generate [src/interceptor.o]!
generate [src/memory.o]!
generate [src/trampoline.o]!
generate [src/platforms/darwin/memory-darwin.o]!
generate [src/platforms/arm64/reader.o]!
generate [src/platforms/arm64/relocator.o]!
generate [src/platforms/arm64/thunker.o]!
generate [src/platforms/arm64/writer.o]!
generate [src/zzdeps/darwin/macho-utils-darwin.o]!
generate [src/zzdeps/darwin/memory-utils-darwin.o]!
generate [src/zzdeps/common/memory-utils-common.o]!
generate [src/zzdeps/posix/memory-utils-posix.o]!
build success for arm64(IOS)!
```