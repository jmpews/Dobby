## HookZz

> [Move to HookZz Getting Started](https://github.com/jmpews/HookZz)

> [Move to HookZzModules](https://github.com/jmpews/HookZzModules)

> [Move to HookZzWebsite](https://github.com/jmpews/HookZzModules)

## What is HookZz?

**a cute hook framwork**. 

**still developing, for arm64/IOS now!**

ref to: [frida-gum](https://github.com/frida/frida-gum) and [minhook](https://github.com/TsudaKageyu/minhook) and [substrate](https://github.com/jevinskie/substrate).

**special thanks to `frida-gum's` perfect code and modular architecture.**


## How it work ?

[Move to HookFrameworkDesign.md](https://github.com/jmpews/HookZz/blob/master/HookFrameworkDesign.md)

## How use it ?

**export 3 func**:

```
// initialize the interceptor and so on.
ZzSTATUS ZzInitialize(void);

// build hook with `replace_call`, `pre_call`, `post_call`, but not enable.
ZzSTATUS ZzBuildHook(zpointer target_ptr, zpointer replace_ptr, zpointer *origin_ptr, zpointer pre_call_ptr, zpointer post_call_ptr);

// enable hook, with `code patch`
ZzSTATUS ZzEnableHook(zpointer target_ptr);
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

and the `pre_call` and `post_call` type is blow.

```
typedef void (*PRECALL)(struct RegState_ *rs);
typedef void (*POSTCALL)(struct RegState_ *rs);
```

## Example

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