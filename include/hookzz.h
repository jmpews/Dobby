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

#ifndef hookzz_h
#define hookzz_h

// clang-format off
#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#include <stdbool.h>
#include <stdint.h>

#if defined(__arm64__) || defined(__aarch64__)
typedef union FPReg_ {
    __int128_t q;
    struct {
        double d1;
        double d2;
    } d;
    struct {
        float f1;
        float f2;
        float f3;
        float f4;
    } f;
} FPReg;

typedef struct _RegState {
    uint64_t sp;

    union {
        uint64_t x[29];
        struct {
            uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21,
                x22, x23, x24, x25, x26, x27, x28;
        } regs;
    } general;

    uint64_t fp;
    uint64_t lr;

    union {
        FPReg q[8];
        struct {
            FPReg q0, q1, q2, q3, q4, q5, q6, q7;
        } regs;
    } floating;
} RegState;
#elif defined(__arm__)
typedef struct _RegState {
    uint32_t sp;

    union {
        uint32_t r[13];
        struct {
            uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
        } regs;
    } general;

    uint32_t lr;
} RegState;
#elif defined(__i386__)
typedef struct _RegState {
} RegState;
#elif defined(__x86_64__)
typedef struct _RegState {
} RegState;
#endif

typedef enum _ZZSTATUS {
    ZZ_UNKOWN = -1,
    ZZ_DONE = 0,
    ZZ_SUCCESS,
    ZZ_FAILED,
    ZZ_DONE_HOOK,
    ZZ_DONE_INIT,
    ZZ_DONE_ENABLE,
    ZZ_ALREADY_HOOK,
    ZZ_ALREADY_INIT,
    ZZ_ALREADY_ENABLED,
    ZZ_NEED_INIT,
    ZZ_NO_BUILD_HOOK
} ZZSTATUS;

typedef struct _CallStack {
    unsigned long call_id;
    struct _ThreadStack *ts;
} CallStack;

typedef struct _ThreadStack {
    unsigned long thread_id;
    unsigned long size;
} ThreadStack;

typedef struct _HookEntryInfo {
    unsigned long hook_id;
    void *hook_address;
} HookEntryInfo;


/* ------- example -------
void common_pre_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info)
{
    puts((char *)rs->general.regs.r0);
    STACK_SET(cs, "format", rs->general.regs.r0, char *);
}

void printf_post_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info)
{
    if (STACK_CHECK_KEY(cs, "format"))
    {
        char *format = STACK_GET(cs, "format", char *);
        puts(format);
    }
}
------- example end ------- */

typedef void (*PRECALL)(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info);
typedef void (*POSTCALL)(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info);
typedef void (*HALFCALL)(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info);

// ------- export API -------

#define STACK_CHECK_KEY(cs, key) (bool)ZzGetCallStackData(cs, key)
#define STACK_GET(cs, key, type) *(type *)ZzGetCallStackData(cs, key)
#define STACK_SET(cs, key, value, type) ZzSetCallStackData(cs, key, &(value), sizeof(type))

/* ------- example -------
void common_pre_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info)
{
    puts((char *)rs->general.regs.r0);
    STACK_SET(cs, "format", rs->general.regs.r0, char *);
}

void printf_post_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info)
{
    if (STACK_CHECK_KEY(cs, "format"))
    {
        char *format = STACK_GET(cs, "format", char *);
        puts(format);
    }
}
------- example end ------- */

void *ZzGetCallStackData(CallStack *callstack_ptr, char *key_str);
bool ZzSetCallStackData(CallStack *callstack_ptr, char *key_str, void *value_ptr, unsigned long value_size);

ZZSTATUS ZzBuildHook(void *target_ptr, void *replace_call_ptr, void **origin_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr, bool try_near_jump);
ZZSTATUS ZzBuildHookAddress(void *target_start_ptr, void *target_end_ptr, PRECALL pre_call_ptr, HALFCALL half_call_ptr, bool try_near_jump);
ZZSTATUS ZzEnableHook(void *target_ptr);

/* ------- example -------

ZzHook((void *)printf_ptr, (void *)fake_printf, (void **)&orig_printf, printf_pre_call, printf_post_call, true);
ZzHookPrePost((void *)printf_ptr, printf_pre_call, printf_post_call, true);
ZzHookReplace((void *)printf_ptr, (void *)fake_printf, (void **)&orig_printf);

------- example end ------- */

ZZSTATUS ZzHook(void *target_ptr, void *replace_ptr, void **origin_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr, bool try_near_jump);
ZZSTATUS ZzHookPrePost(void *target_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr);
ZZSTATUS ZzHookReplace(void *target_ptr, void *replace_ptr, void **origin_ptr);
ZZSTATUS ZzHookAddress(void *target_start_ptr, void *target_end_ptr, PRECALL pre_call_ptr, HALFCALL half_call_ptr);

// enable debug info
void ZzEnableDebugMode(void);

// runtime code patch
ZZSTATUS ZzRuntimeCodePatch(void *address, void *code_data, unsigned long code_length);

ZZSTATUS ZzHookGOT(const char *name, void *replace_ptr, void **origin_ptr, PRECALL pre_call_ptr,
                   POSTCALL post_call_ptr);

ZZSTATUS ZzDisableHook(void *target_ptr);

// ------- export API end -------

#if defined(__arm64__) || defined(__aarch64__)
#if defined(__APPLE__) && defined(__MACH__)
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#define TARGET_IS_IOS 1
#endif
#endif
#endif
#ifdef TARGET_IS_IOS
ZZSTATUS StaticBinaryInstrumentation(void *target_fileoff, void *replace_call_ptr, void **origin_ptr, PRECALL pre_call_ptr,
                        POSTCALL post_call_ptr);
#endif

#ifdef __cplusplus
}
#endif //__cplusplus
#endif
