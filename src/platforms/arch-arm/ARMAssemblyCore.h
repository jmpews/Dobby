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

#define MULTICLASS_3(a, b, c) a_##b_##b

typedef enum {
  MULTICLASS_3(XI, AXI, BLXi),
  MULTICLASS_3(XI, ABXI, BL),
} ARMInstId;

typedef enum {
  MULTICLASS_3(XI, T2PCOneRegImm, t2ADR),
} Thumb2InstId;

typedef struct {
  uint32_t inst32;
  uint32_t mask32;
} ARMInstructionX, Thumb2InstructionX;

typedef struct {
  uint16_t inst32;
  uint16_t mask32;
} ThumbInstructionX;

void BIT32SET(uint32_t *inst32, int start, int len, uint32_t v);
void BIT32SETMASK(uint32_t *inst32, int start, int len);
void BIT32MASKSET(uint32_t *inst32, uint32_t *mask32, int start, int len, uint32_t v);
void BIT32GET(uint32_t inst32, int start, int len, uint32_t *v);

ARMInstId getInstType(uint32_t inst32);

#ifdef __cplusplus
}
#endif

#endif
