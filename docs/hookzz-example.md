# HookZz example

> [Move to HookZz Getting Started](https://jmpews.github.io/zzpp/getting-started/)

> [Move to HookZz Example](https://jmpews.github.io/zzpp/hookzz-example/)

> [Move to HookZz docs](https://jmpews.github.io/zzpp/hookzz-docs/)

> [Move to HookZzModules](https://github.com/jmpews/HookZzModules)

> [Move to HookZzWebsite](https://jmpews.github.io/zzpp/)


# Simple Example

#### 1. use `ZzBuildHookAddress`

hook at address, and specify the hook length. (i.e. hook a piece of code.)

```
#
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

void hook_pre_call(RegState *rs, ZzCallStack *stack)
{
    unsigned long request = *(unsigned long *)(&rs->general.regs.x16);
    printf("request is: %ld\n", request);
}

void hook_half_call(RegState *rs, ZzCallStack *stack)
{
    unsigned long x0 = (unsigned long)(rs->general.regs.x0);
    printf("getpid() return %ld\n", x0);
}

__attribute__((constructor)) void test_hook_address()
{
    ZzInitialize();
    void *hack_this_function_ptr = (void *)hack_this_function;
    // hook address with only `pre_call`
    // ZzBuildHookAddress(hack_this_function_ptr + 8, hack_this_function_ptr + 12, (void *)hook_pre_call, NULL);

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

#### 2. use `ZzBuildHook`

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

void objcMethod_pre_call(RegState *rs, ZzCallStack *stack) {
  zpointer t = 0x1234; 
  STACK_SET(stack ,"key_x", t, void *);
  STACK_SET(stack ,"key_y", t, zpointer);
  NSLog(@"hookzz OC-Method: -[ViewController %s]",
        (zpointer)(rs->general.regs.x1));
}

void objcMethod_post_call(RegState *rs, ZzCallStack *stack) {
  zpointer x = STACK_GET(stack, "key_x", void *);
  zpointer y = STACK_GET(stack, "key_y", zpointer);
  NSLog(@"function over, and get 'key_x' is: %p", x);
  NSLog(@"function over, and get 'key_y' is: %p", y);
}
+ (void)zzMethodSwizzlingHook {
  Class hookClass = objc_getClass("UIViewController");
  SEL oriSEL = @selector(viewWillAppear:);
  Method oriMethod = class_getInstanceMethod(hookClass, oriSEL);
  IMP oriImp = method_getImplementation(oriMethod);

  ZzInitialize();
  ZzBuildHook((void *)oriImp, NULL, NULL, (zpointer)objcMethod_pre_call, (zpointer)objcMethod_post_call);
  ZzEnableHook((void *)oriImp);
}

@end
```

**hook oc method output:**

```
2017-08-18 00:21:07.976 T007[1073:43815] hookzz OC-Method: -[ViewController viewWillAppear:]
2017-08-18 00:21:07.976 T007[1073:43815] function over, and get 'key_x' is: 0x1234
2017-08-18 00:21:07.976 T007[1073:43815] function over, and get 'key_y' is: 0x1234
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
void syscall_pre_call(RegState *rs) {
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

void objcMethod_pre_call(RegState *rs) {
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

