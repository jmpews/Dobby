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

#ifndef REGISTER_STATE_STRUCT
#define REGISTER_STATE_STRUCT
#if defined(__arm64__) || defined(__aarch64__)
#define Tx(type) type##arm64
#define TX() type##ARM64
#define xT() arm64##type
#define XT() ARM64##type
typedef union _FPReg {
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
    uint64_t dmmpy_0;

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
#define Tx(type) type##arm
#define TX() type##ARM
#define xT() arm##type
#define XT() ARM##type
typedef struct _RegState {
    uint32_t dummy_0;
    uint32_t dummy_1;

    union {
        uint32_t r[13];
        struct {
            uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
        } regs;
    } general;

    uint32_t lr;
} RegState;
#elif defined(__i386__)
#define Tx(type) type##arm
#define TX() type##ARM
#define xT() arm##type
#define XT() ARM##type
typedef struct _RegState {
} RegState;
#elif defined(__x86_64__)
#define Tx(type) type##x64
#define TX() type##X64
#define xT() x64##type
#define XT() X64##type
typedef struct _RegState {
} RegState;
#endif

#define REG_SP(rs) (void *)((uintptr_t)rs + sizeof(RegState))
#endif

typedef enum _RetStatus {
    RS_UNKOWN = -1,
    RS_DONE = 0,
    RS_SUCCESS,
    RS_FAILED,
    RS_DONE_HOOK,
    RS_DONE_INIT,
    RS_DONE_ENABLE,
    RS_ALREADY_HOOK,
    RS_ALREADY_INIT,
    RS_ALREADY_ENABLED,
    RS_NEED_INIT,
    RS_NO_BUILD_HOOK
} RetStatus;

typedef enum _ZZHOOKTYPE {
//  HOOK_TYPE_SINGLE_INSTRUCTION_DELETED = 0,
    HOOK_TYPE_FUNCTION_via_PRE_POST = 0,
    HOOK_TYPE_FUNCTION_via_REPLACE,
    HOOK_TYPE_FUNCTION_via_GOT,
    HOOK_TYPE_DBI
}ZZHOOKTYPE;

typedef struct _CallStackPublic {
    unsigned long call_id;
    struct _ThreadStack *ts;
} CallStackPublic;

typedef struct _ThreadStackPublic {
    unsigned long thread_id;
    unsigned long size;
} ThreadStackPublic;

typedef struct _HookEntryInfo {
    unsigned long hook_id;
    void *hook_address;
} HookEntryInfo;

typedef void (*PRECALL)(RegState *rs, ThreadStackPublic *ts, CallStackPublic *cs, const HookEntryInfo *info);
typedef void (*POSTCALL)(RegState *rs, ThreadStackPublic *ts, CallStackPublic *cs, const HookEntryInfo *info);
typedef void (*STUBCALL)(RegState *rs, const HookEntryInfo *info);

#define STACK_CHECK_KEY(cs, key) (bool)CallStackGetThreadLocalData(cs, key)
#define STACK_GET(cs, key, type) *(type *)CallStackGetThreadLocalData(cs, key)
#define STACK_SET(cs, key, value, type) CallStackSetThreadLocalData(cs, key, &(value), sizeof(type))

void *CallStackGetThreadLocalData(CallStackPublic *callstack_ptr, char *key_str);
bool CallStackSetThreadLocalData(CallStackPublic *callstack_ptr, char *key_str, void *value_ptr, unsigned long value_size);

RetStatus ZzHook(void *target_ptr, void *replace_call, void **origin_call_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr, bool try_near_jump);
RetStatus ZzHookPrePost(void *target_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr);
RetStatus ZzHookReplace(void *target_ptr, void *replace_call, void **origin_call_ptr);

// got hook (only support darwin)
RetStatus ZzHookGOT(const char *name, void *replace_call, void **origin_call_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr);

// dynamic binary instrumentation
RetStatus ZzDynamicBinaryInstrumentation(void *address, STUBCALL stub_call_ptr);

// hook only one instruciton with instruction address
// void ZzHookSingleInstruction(void *insn_address, PRECALL pre_call_ptr, POSTCALL post_call_ptr, bool try_near_jump);

// runtime code patch
RetStatus ZzRuntimeCodePatch(void *address, void *code_data, unsigned long code_length);

// enable debug info
void DebugLogControlerEnableLog();

// disable hook
RetStatus ZzDisableHook(void *target_ptr);

#if defined(__arm64__) || defined(__aarch64__)
#if defined(__APPLE__) && defined(__MACH__)
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#define TARGET_IS_IOS 1
#endif
#endif
#endif
#ifdef TARGET_IS_IOS
RetStatus StaticBinaryInstrumentation(void *target_fileoff, void *replace_call_ptr, void **origin_call_ptr, PRECALL pre_call_ptr,
                        POSTCALL post_call_ptr);
#endif

#ifdef __cplusplus
}
#endif //__cplusplus
#endif
