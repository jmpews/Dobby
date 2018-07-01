#ifndef hookzz_h
#define hookzz_h

// clang-format off
#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#include <stdbool.h>
#include <stdint.h>

typedef uintptr_t zz_addr_t;
typedef void * zz_ptr_t;

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
    RS_FAILED
} RetStatus;

typedef enum _HookType {
//  HOOK_TYPE_SINGLE_INSTRUCTION_DELETED = 0,
    HOOK_TYPE_FUNCTION_via_PRE_POST = 0,
    HOOK_TYPE_FUNCTION_via_REPLACE,
    HOOK_TYPE_FUNCTION_via_GOT,
    HOOK_TYPE_INSTRUCTION_via_DBI
}HookType;

typedef struct _CallStackPublic {
    uintptr_t call_id;
} CallStackPublic;

typedef struct _ThreadStackPublic {
    uintptr_t thread_id;
    unsigned long call_stack_count;
} ThreadStackPublic;

typedef struct _HookEntryInfo {
    uintptr_t hook_id;
    void *target_address;
} HookEntryInfo;

typedef void (*PRECALL)(RegState *rs, ThreadStackPublic *tsp, CallStackPublic *csp, const HookEntryInfo *info);
typedef void (*POSTCALL)(RegState *rs, ThreadStackPublic *tsp, CallStackPublic *csp, const HookEntryInfo *info);
typedef void (*DBICALL)(RegState *rs, const HookEntryInfo *info);

void call_stack_kv_set(CallStackPublic *csp, char *key, void *value);

void *call_stack_kv_get(CallStackPublic *csp, char *key);

// open near jump, use code cave & b xxx
void zz_enable_near_jump();

// close near jump, use `ldr x17, #0x8; br x17; .long 0x0; .long 0x0`
void zz_disable_near_jump();

// use pre_call and post_call wrap a function
RetStatus ZzWrap(void *function_address, PRECALL pre_call, POSTCALL post_call);

// use inline hook to replace function
RetStatus ZzReplace(void *function_address, void *replace_call, void **origin_call);

// use pre_call and post_call wrap a GOT(imported) function
RetStatus ZzWrapGOT(void *image_header, char *image_name, char *function_name, PRECALL pre_call, POSTCALL post_call);

// replace got
RetStatus ZzReplaceGOT(void *image_header, char *image_name, char *function_name, void *replace_call, void **origin_call);

// hook instruction with DBI
RetStatus ZzDynamicBinaryInstrumentation(void *inst_address, DBICALL dbi_call);

#ifdef __cplusplus
}
#endif //__cplusplus
#endif
