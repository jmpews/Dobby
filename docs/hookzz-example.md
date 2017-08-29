# HookZz example

> [Move to HookZz Getting Started](https://jmpews.github.io/zzpp/getting-started/)

> [Move to HookZz Example](https://jmpews.github.io/zzpp/hookzz-example/)

> [Move to HookZz docs](https://jmpews.github.io/zzpp/hookzz-docs/)

> [Move to HookZzModules](https://github.com/jmpews/HookZzModules)

> [Move to HookZzWebsite](https://jmpews.github.io/zzpp/)


## Simple Example

#### 1. use `ZzBuildHookAddress`

hook at address, and specify the hook length. (i.e. hook a piece of code.)

```c
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

void hook_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    unsigned long request = *(unsigned long *)(&rs->general.regs.x16);
    printf("x16 is: %ld\n", request);
}

void hook_half_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    unsigned long x0 = (unsigned long)(rs->general.regs.x0);
    printf("getpid() return %ld\n", x0);
}

__attribute__((constructor)) void test_hook_address()
{
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

```c
#include "hookzz.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>

@interface HookZz : NSObject

@end

@implementation HookZz

+ (void)load {
  [self zzMethodSwizzlingHook];
}

void objcMethod_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
  zpointer t = 0x1234; 
  STACK_SET(callstack ,"key_x", t, void *);
  STACK_SET(callstack ,"key_y", t, zpointer);
  NSLog(@"hookzz OC-Method: -[UIViewController %s]",
        (zpointer)(rs->general.regs.x1));
}

void objcMethod_post_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
  zpointer x = STACK_GET(callstack, "key_x", void *);
  zpointer y = STACK_GET(callstack, "key_y", zpointer);
  NSLog(@"function over, and get 'key_x' is: %p", x);
  NSLog(@"function over, and get 'key_y' is: %p", y);
}

+ (void)zzMethodSwizzlingHook {
  Class hookClass = objc_getClass("UIViewController");
  SEL oriSEL = @selector(viewWillAppear:);
  Method oriMethod = class_getInstanceMethod(hookClass, oriSEL);
  IMP oriImp = method_getImplementation(oriMethod);

  ZzBuildHook((void *)oriImp, NULL, NULL, objcMethod_pre_call, objcMethod_post_call);
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

#### 3. use `ZzRuntimeCodePatch`

use `nop` to patch all `svc #0x80`, try to bypass `svc #0x80` AntiDebug, but can't bypass `check_svc_integrity`.

[Move to AntiDebug-check_svc_integrity](https://github.com/jmpews/HookZzModules/blob/master/AntiDebug/AntiDebug.m#L31)

tips : `ZzRuntimeCodePatch` usually works with [MachoParser](https://github.com/jmpews/MachoParser)

```c
__attribute__((constructor)) void patch_svc_x80_with_nop() {
    zaddr svc_x80_addr;
    zaddr curr_addr, text_start_addr, text_end_addr;
    uint32_t svc_x80_byte = 0xd4001001;
    
    const struct mach_header *header = _dyld_get_image_header(0);
    struct segment_command_64 *seg_cmd_64 = zz_macho_get_segment_64_via_name((struct mach_header_64 *)header, (char *)"__TEXT");
    zsize slide = (zaddr)header - (zaddr)seg_cmd_64->vmaddr;
    
    struct section_64 *sect_64 = zz_macho_get_section_64_via_name((struct mach_header_64 *)header, (char *)"__text");
    
    text_start_addr = slide + (zaddr)sect_64->addr;
    text_end_addr = text_start_addr + sect_64->size;
    curr_addr = text_start_addr;

    while (curr_addr < text_end_addr) {
        svc_x80_addr = (zaddr)zz_vm_search_data((zpointer)curr_addr, (zpointer)text_end_addr, (zbyte *)&svc_x80_byte, 4);
        if (svc_x80_addr) {
      NSLog(@"patch svc #0x80 with 'nop' at %p with aslr (%p without aslr)",
            (void *)svc_x80_addr, (void *)(svc_x80_addr -
            slide));
      unsigned long nop_bytes = 0xD503201F;
      ZzRuntimeCodePatch(svc_x80_addr, (zpointer)&nop_bytes, 4);
      curr_addr = svc_x80_addr + 4;
    } else {
      break;
    }
  }
}
```

**[Move to AntiDebugBypass Detail](https://github.com/jmpews/HookZzModules/tree/master/AntiDebugBypass)**

## Advanced Example

#### 1. use `replace_call` bypass syscall-antidebug

**TIPS: how to hook variadic function? fake a origin function stack.**

```c
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
    
    // must understand the principle of `function call`. `parameter pass` is
    // before `switch to target` so, pass the whole `stack`, it just actually
    // faked an original stack. Do not pass a large structure,  will be replace with
    // a `hidden memcpy`.
    int x = orig_syscall(number, stack[0], stack[1], stack[2], stack[3], stack[4],
                         stack[5], stack[6], stack[7]);
    return x;
}

__attribute__((constructor)) void patch_ptrace_sysctl_syscall() {

  zpointer syscall_ptr = (void *)syscall;
  ZzBuildHook((void *)syscall_ptr, (void *)fake_syscall, (void
  **)&orig_syscall,
              NULL, NULL);
  ZzEnableHook((void *)syscall_ptr);
}
```

**[Move to AntiDebugBypass Detail](https://github.com/jmpews/HookZzModules/tree/master/AntiDebugBypass)**

#### 2. use `pre_call` bypass syscall-antidebug

```c
void syscall_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
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
    #if 0
    ZzBuildHook((void *)syscall_ptr, NULL, NULL, syscall_pre_call, NULL);
    ZzEnableHook((void *)syscall_ptr);
    #endif
}
```

**[Move to AntiDebugBypass Detail](https://github.com/jmpews/HookZzModules/tree/master/AntiDebugBypass)**


#### 3. hook Objective-C method.

read `<objc/runtime.h>` funciton.

```c
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

#### 4. hook `svc #0x80`

```c
void hook_svc_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    int num_syscall;
    int request;
    num_syscall = (int)(uint64_t)(rs->general.regs.x16);
    request = (int)(uint64_t)(rs->general.regs.x0);
    
    if (num_syscall == SYS_syscall) {
        int arg1 = (int)(uint64_t)(rs->general.regs.x1);
        if (request == SYS_ptrace && arg1 == PT_DENY_ATTACH) {
            *(unsigned long *)(&rs->general.regs.x1) = 10;
            NSLog(@"[AntiDebugBypass] catch 'SVC #0x80; syscall(ptrace)' and bypass");
        }
        
    } else if (num_syscall == SYS_ptrace) {
        request = (int)(uint64_t)(rs->general.regs.x0);
        if (request == PT_DENY_ATTACH) {
            *(unsigned long *)(&rs->general.regs.x0) = 10;
            NSLog(@"[AntiDebugBypass] catch 'SVC-0x80; ptrace' and bypass");
        }
    } else if(num_syscall == SYS_sysctl) {
        STACK_SET(callstack, (char *)"num_syscall", num_syscall, int);
        STACK_SET(callstack, (char *)"info_ptr", rs->general.regs.x2, zpointer);
    }
}

void hook_svc_half_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    // emmm... little long...
    if(STACK_CHECK_KEY(callstack, (char *)"num_syscall")) {
        int num_syscall = STACK_GET(callstack, (char *)"num_syscall", int);
        struct kinfo_proc *info = STACK_GET(callstack, (char *)"info_ptr", struct kinfo_proc *);
        if (num_syscall == SYS_sysctl)
        {
            NSLog(@"[AntiDebugBypass] catch 'SVC-0x80; sysctl' and bypass");
            info->kp_proc.p_flag &= ~(P_TRACED);
        }
    }
}

__attribute__((constructor)) void hook_svc_x80() {
    zaddr svc_x80_addr;
    zaddr curr_addr, text_start_addr, text_end_addr;
    uint32_t svc_x80_byte = 0xd4001001;
    
    const struct mach_header *header = _dyld_get_image_header(0);
    struct segment_command_64 *seg_cmd_64 = zz_macho_get_segment_64_via_name((struct mach_header_64 *)header, (char *)"__TEXT");
    zsize slide = (zaddr)header - (zaddr)seg_cmd_64->vmaddr;
    
    struct section_64 *sect_64 = zz_macho_get_section_64_via_name((struct mach_header_64 *)header, (char *)"__text");
    
    text_start_addr = slide + (zaddr)sect_64->addr;
    text_end_addr = text_start_addr + sect_64->size;
    curr_addr = text_start_addr;
    
    while (curr_addr < text_end_addr) {
        svc_x80_addr = (zaddr)zz_vm_search_data((zpointer)curr_addr, (zpointer)text_end_addr, (zbyte *)&svc_x80_byte, 4);
        if (svc_x80_addr) {
            NSLog(@"hook svc #0x80 at %p with aslr (%p without aslr)",
                  (void *)svc_x80_addr, (void *)(svc_x80_addr - slide));
            ZzBuildHookAddress((void *)svc_x80_addr, (void *)(svc_x80_addr + 4),
                               hook_svc_pre_call, hook_svc_half_call);
            ZzEnableHook((void *)svc_x80_addr);
            curr_addr = svc_x80_addr + 4;
        } else {
            break;
        }
    }
}
```

**[Move to AntiDebugBypass Detail](https://github.com/jmpews/HookZzModules/tree/master/AntiDebugBypass)**

#### 5. hook `objc_msgSend`

**[Move to hook_objc_msgSend Detail](https://github.com/jmpews/HookZzModules/tree/master/hook_objc_msgSend)**

#### 6. hook `MGCopyAnswer`

**[Move to hook_MGCopyAnswer Detail](https://github.com/jmpews/HookZzModules/tree/master/hook_MGCopyAnswer)**