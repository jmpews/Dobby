#ifndef dobby_h
#define dobby_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

void log_set_level(int level);
void log_switch_to_syslog();
void log_switch_to_file(const char *path);

typedef enum {
  kMemoryOperationSuccess,
  kMemoryOperationError,
  kNotSupportAllocateExecutableMemory,
  kNotEnough,
  kNone
} MemoryOperationError;

typedef uintptr_t addr_t;
typedef uint32_t addr32_t;
typedef uint64_t addr64_t;
typedef void (*func_t)();
typedef void (*asm_func_t)();

MemoryOperationError CodePatch(void *address, uint8_t *buffer, uint32_t buffer_size);

#if defined(__arm64__) || defined(__aarch64__)

#define ARM64_TMP_REG_NDX_0 17

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

// register context
typedef struct {
  uint64_t dmmpy_0; // dummy placeholder
  uint64_t sp;

  uint64_t dmmpy_1; // dummy placeholder
  union {
    uint64_t x[29];
    struct {
      uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22,
          x23, x24, x25, x26, x27, x28;
    } regs;
  } general;

  uint64_t fp;
  uint64_t lr;

  union {
    FPReg q[32];
    struct {
      FPReg q0, q1, q2, q3, q4, q5, q6, q7;
      // [!!! READ ME !!!]
      // for Arm64, can't access q8 - q31, unless you enable full floating-point register pack
      FPReg q8, q9, q10, q11, q12, q13, q14, q15, q16, q17, q18, q19, q20, q21, q22, q23, q24, q25, q26, q27, q28, q29,
          q30, q31;
    } regs;
  } floating;
} RegisterContext;
#elif defined(__arm__)
typedef struct {
  uint32_t dummy_0;
  uint32_t dummy_1;

  uint32_t dummy_2;
  uint32_t sp;

  union {
    uint32_t r[13];
    struct {
      uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
    } regs;
  } general;

  uint32_t lr;
} RegisterContext;
#elif defined(_M_IX86) || defined(__i386__)
typedef struct _RegisterContext {
  uint32_t dummy_0;
  uint32_t esp;

  uint32_t dummy_1;
  uint32_t flags;

  union {
    struct {
      uint32_t eax, ebx, ecx, edx, ebp, esp, edi, esi;
    } regs;
  } general;

} RegisterContext;
#elif defined(_M_X64) || defined(__x86_64__)
typedef struct {
  uint64_t dummy_0;
  uint64_t rsp;

  union {
    struct {
      uint64_t rax, rbx, rcx, rdx, rbp, rsp, rdi, rsi, r8, r9, r10, r11, r12, r13, r14, r15;
    } regs;
  } general;

  uint64_t dummy_1;
  uint64_t flags;
} RegisterContext;
#endif

#define RT_FAILED -1
#define RT_SUCCESS 0
typedef enum { RS_FAILED = -1, RS_SUCCESS = 0 } RetStatus;

// DobbyWrap <==> DobbyInstrument, so use DobbyInstrument instead of DobbyWrap
#if 0
// wrap function with pre_call and post_call
typedef void (*PreCallTy)(RegisterContext *ctx, const HookEntryInfo *info);
typedef void (*PostCallTy)(RegisterContext *ctx, const HookEntryInfo *info);
int DobbyWrap(void *function_address, PreCallTy pre_call, PostCallTy post_call);
#endif

// return dobby build date
const char *DobbyBuildVersion();

// function inline hook
int DobbyHook(void *address, func_t replace_func, func_t *origin_func);

// dynamic binary instruction instrument
// [!!! READ ME !!!]
// for Arm64, can't access q8 - q31, unless enable full floating-point register pack
typedef void (*instrument_callback_t)(void *address, RegisterContext *ctx);
int DobbyInstrument(void *address, instrument_callback_t handler);

int DobbyDestroy(void *address);

void *DobbySymbolResolver(const char *image_name, const char *symbol_name);

int DobbyGotHook(char *image_name, char *symbol_name, func_t fake_func, func_t *orig_func);

// [!!! READ ME !!!]
// for arm, Arm64, dobby will try use b xxx instead of ldr absolute indirect branch
// for x64, dobby always use absolute indirect jump
#if defined(__arm__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_X64) || defined(__x86_64__)
void dobby_enable_near_branch_trampoline();
void dobby_disable_near_branch_trampoline();
#endif

#ifdef __cplusplus
}
#endif

#endif
