#ifndef hookzz_h
#define hookzz_h

// clang-format off
#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#include <stdbool.h>
#include <stdint.h>

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

typedef struct _RegisterContext {
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
} RegisterContext;
#elif defined(__arm__)
#define Tx(type) type##arm
#define TX() type##ARM
#define xT() arm##type
#define XT() ARM##type
typedef struct _RegisterContext {
    uint32_t dummy_0;
    uint32_t dummy_1;

    union {
        uint32_t r[13];
        struct {
            uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
        } regs;
    } general;

    uint32_t lr;
} RegisterContext;
#elif defined(_M_X64) || defined(__x86_64__)
typedef struct _RegisterContext {
  uint64_t dummy;
  union {
    struct {
      uint64_t dummy;
    } regs;
  } general;

} RegisterContext;
#endif

// #define REG_SP(reg_ctx) (void *)((uintptr_t)reg_ctx + sizeof(RegisterContext))

typedef enum _RetStatus {
    kUnknown = -1,
    RS_DONE = 0,
    RS_SUCCESS,
    RS_FAILED
} RetStatus;

typedef enum _PackageType {
  kFunctionWrapper,
  kFunctionInlineHook,
  kDynamicBinaryInstrumentation
} PackageType, HookEntryType;

typedef struct _HookEntryInfo {
   uintptr_t hook_id;
   union {
    void *target_address;
    void *function_address;
    void *instruction_address;
  }; 
}HookEntryInfo;

typedef void (*PRECALL)(RegisterContext *reg_ctx, const HookEntryInfo *info);
typedef void (*POSTCALL)(RegisterContext *reg_ctx, const HookEntryInfo *info);
typedef void (*DBICALL)(RegisterContext *reg_ctx, const HookEntryInfo *info);

// use `b xxx` as trampoline 
RetStatus zz_enable_arm_arm64_b_branch();

// disable
RetStatus zz_disable_arm_arm64_b_branch();

// wrap function with pre_call and post_call
RetStatus ZzWrap(void *function_address, PRECALL pre_call, POSTCALL post_call);

// replace function
RetStatus ZzReplace(void *function_address, void *replace_call, void **origin_call);

// dynamic binary instrument for instruction
RetStatus ZzDynamicBinaryInstrumentation(void *inst_address, DBICALL dbi_call);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif
