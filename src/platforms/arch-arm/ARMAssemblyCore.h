//
// Created by z on 2018/5/7.
//

#ifndef ARM_ASSEMBLY_CORE_H
#define ARM_ASSEMBLY_CORE_H

#include <stdarg.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MULTICLASS(parent, child) parent##_##child

typedef enum { DECODE, ENCODE, INIT } OperationType;

typedef enum { Invalid, Register, Immediate } OperandType;

typedef enum {
  REG_R0 = 0,
  REG_R1,
  REG_R2,
  REG_R3,
  REG_R4,
  REG_R5,
  REG_R6,
  REG_R7,
  REG_R8,
  REG_R9,
  REG_R10,
  REG_R11,
  REG_R12,

  REG_PC,
  REG_FP,
  REG_LR,
  REG_SP
} ARM64RegID;

#define class_0_parent(a) a
#define class_1_parent(a, b) a##__##b
#define class_2_parent(a, b, c) a##__##b_##c
#define class_3_parent(a, b, c, d) a##__##b_##c_##d

// struct _class_t {
//   char *class_name;
//   // max number parent classes == 4
//   struct _class_t *parent_classes[4];
// } class_t;

// struct _class_t **g_class_ptr_s[256];

// #include <stdarg.h>
// void register_class(char *class_name, ...) {
//   va_list args;
//   va_start(args, class_name);
//   while (1) {
//     int var_int = va_arg(args, int);
//   }
//   va_end(args);
// }

typedef enum {
  MULTICLASS_3(XI, AXI, BLXi),
  MULTICLASS_3(XI, ABXI, BL),
} ARMInstId;

typedef enum {
  MULTICLASS_4(t2B, T2I, Thumb2I, InstARM),
  MULTICLASS_4(t2Bcc, T2I, Thumb2I, InstARM),
  MULTICLASS_5(t2ADR, T2PCOneRegImm, T2XI, Thumb2XI, InstARM)
} Thumb2InstId;

typedef enum {
  class_3_parent(tADR, T1I, T1Encoding, Sched),
  class_3_parent(tBcc, T1I, T1BranchCond, Sched),
  class_3_parent(tBL, TIx2, Requires, Sched)
} ThumbInstId;

typedef struct {
  uint32_t inst32;
  uint32_t mask32;
} ARMInstructionX, ThumbInstructionX, Thumb2InstructionX;

void BIT32SET(uint32_t *inst32, int start, int len, uint32_t v);
void BIT32SETMASK(uint32_t *inst32, int start, int len);
void BIT32MASKSET(uint32_t *inst32, uint32_t *mask32, int start, int len, uint32_t v);
void BIT32GET(uint32_t inst32, int start, int len, uint32_t *v);

ARMInstId getInstType(uint32_t inst32);

#ifdef __cplusplus
}
#endif

#endif
