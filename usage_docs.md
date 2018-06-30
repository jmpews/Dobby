# README ?

## Prologue

refer `demo/HookZzAndroidDemoTemplate.zip` or ``demo/HookZzIOSDemoTemplate.zip`` 

## Basic Usage 

大部分的对外暴露的 API 都在 `hookzz.h`.

对于基本的 hook 要求, 可以使用下面三个函数. 

```
ZZSTATUS ZzHook(void *target_ptr, void *replace_ptr, void **origin_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr, bool try_near_jump);

ZZSTATUS ZzHookPrePost(void *target_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr);

ZZSTATUS ZzHookReplace(void *target_ptr, void *replace_ptr, void **origin_ptr);
```

其中 `ZzHookPrePost` & `ZzHookReplace` 只是对 `ZzHook` 的封装. 并且并没有开启 `try_near_jump`(参见QA).

如果 crash 了怎么办? 见下文.

HookZz 提供了在函数的 Pre 和 Post 阶段直接访问寄存器的能力, 也就说, 可能需要你自己**判断参数在哪个寄存器**. 由于是直接提供寄存器的控制, 所以你可以不用管被 hook 函数是否是变参函数.  可以参考各种架构手册的调用规约. [ARM64 Call Convention](http://infocenter.arm.com/help/topic/com.arm.doc.ihi0055b/IHI0055B_aapcs64.pdf)

可以通过下面的 demo, 看出来如何修改寄存器的值, 如何进行 `pre & post hook`.

```
int (*orig_printf)(const char * format, ...);
int fake_printf(const char * format, ...) {
    puts("call printf");

    char *stack[16];
    void *args_stack;
    va_list args;
    va_start(args, format);
    args_stack = *(void **)&args;
    memcpy(stack, args_stack, sizeof(char *) * 16);
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

void printf_post_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info) {
    if (STACK_CHECK_KEY(cs, "format")) {
        char *format = STACK_GET(cs, "format", char *);
        puts(format);
    }
    puts("<<< printf-post-call");
}

#if defined(__arm64__) || defined(__aarch64__)
void printf_pre_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info) {
    puts((char *)rs->general.regs.x0);
    STACK_SET(cs, "format", rs->general.regs.x0, char *);
    puts(">>> printf-pre-call");
}
#else
void printf_pre_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info) {
    puts((char *)rs->general.regs.r0);
    STACK_SET(cs, "format", rs->general.regs.r0, char *);
    puts(">>> printf-pre-call");
}
#endif
__attribute__((constructor)) void test_hook_printf() {
    void *printf_ptr = (void *)printf;

    HookZzDebugInfoEnable();
    ZzHook((void *)printf_ptr, (void *)fake_printf, (void **)&orig_printf, printf_pre_call,
           printf_post_call, false);


    printf("HookZzzzzzz, %d, %p, %d, %d, %d, %d, %d, %d, %d\n", 1, (void *)2, 3, (char)4, (char)5,
           (char)6, 7, 8, 9);
}
```


## Advanced with Instruction Instrument

如何进行一些指令级的黑科技? hook 一条指令? 在指令执行前进行插桩? 如何 patch 几条指令? 

你需要这两个 API.

```
ZZSTATUS ZzHookOneInstruction(void *insn_address, PRECALL pre_call_ptr, POSTCALL post_call_ptr, bool try_near_jump);
ZZSTATUS ZzDynamicBinaryInstrumentation(void *address, STUBCALL stub_call_ptr);
ZZSTATUS ZzRuntimeCodePatch(void *address, void *code_data, unsigned long code_length);
```

`ZzHookOneInstruction` 函数可以用来对指令地址进行 hook, 也就是 hook 一条指令, 在指令执行的前后添加一个可以直接控制寄存器的函数.

`ZzDynamicBinaryInstrumentation` 函数可以进行指令集插桩, 在一条指令前加可以直接访问控制所有寄存器的 stub 处理函数.

`ZzRuntimeCodePatch` 函数可以直接进行 runtime code patch 指令.

具体可以参考下面的 demo. 

```
__attribute__((__naked__)) static void sorry_to_exit() {
#ifdef __arm__
    __asm__ volatile(
    "mov r0, #0\n"
            "mov r12, #1\n"
            "svc #0x80");
#endif
}

void getpid_pre_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info) {
}

void
getpid_insn_leave_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info) {
    pid_t r0 = (pid_t) (rs->general.regs.r0);
    LOGI("getpid() svc return at r0 is: %d\n", r0);
}

void getpid_stub_call(RegState *rs, const HookEntryInfo *info) {
    LOGI(">>> call DBI stub");
    pid_t r0 = (pid_t) (rs->general.regs.r0);
    LOGI("getpid() svc return at r0 is: %d\n", r0);

}



__attribute__((constructor)) void test_hook_address() {
    HookZzDebugInfoEnable();
    unsigned long getpid_addr = (unsigned long) (void (*)()) getpid;
    #if 0
    ZzHookOneInstruction((char *) getpid + 8, getpid_pre_call, getpid_insn_leave_call, false);
    #else
	ZzDynamicBinaryInstrumentation((char *) getpid + 0xc, getpid_stub_call);
	#endif
    pid_t pid = getpid();
    LOGI("fake getpid() return: %d\n", pid);

    unsigned long sorry_to_exit_addr = (unsigned long) (void (*)()) sorry_to_exit;
    unsigned long sorry_to_exit_aligned_addr = sorry_to_exit_addr & ~(unsigned long)1;
    unsigned long zero_bytes = 0x00;
    ZzRuntimeCodePatch((char *)sorry_to_exit_aligned_addr + 8, &zero_bytes, 1);
    ZzRuntimeCodePatch((char *)sorry_to_exit_aligned_addr + 9, &zero_bytes, 1);

    sorry_to_exit();

    printf("hack success -.0\n");
}
```

## HookZz 的 iOS 下 trick

如果需要对 `objc_msgSend` 函数进行 hook, 怎么做? 

一种方法是采用 inlinehook, 这种会导致跟踪所有的 oc 方法调用, 包含系统库的.

这里使用另外一种方法, 让 HookZz 和 fishhook 进行配合. 只 trace 走自身二进制内的 GOT stub 的 oc 方法调用.


```
ZZSTATUS ZzHookGOT(const char *name, void *replace_ptr, void **origin_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr);

```

对于 demo, 请转至 `demo/` 下查看.


## QA

**1. 什么是 `try_near_jump` ?**

尝试使用 `b xxx` 进行跳转. 默认会使用

ARM/Thumb:

```
ldr pc, [pc, #-4]
.long target_address
```

ARM64:

```
ldr x17, #4
.long target_address
```

使用 `try_near_jump` 会减少修复指令书. 可以在发生 crash 时, 切换该选项尝试.

**2. 如果发生了 crash 怎么办?**

先尝试修改成 `try_near_jump`. 如果无效, 则尝试提交 issue.
