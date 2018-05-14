//
// Created by z on 2018/5/7.
//

#ifndef HOOKZZANDROIDDEMOTEMPLATE_ARM64ASSEMBLER_H
#define HOOKZZANDROIDDEMOTEMPLATE_ARM64ASSEMBLER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ARM64InstructionX ARM64InstructionX

#define MULTICLASS(parent, child) parent##_##child

typedef enum { TReg32, TReg64 } RegBitType;

typedef enum {
  REG_X0 = 0,
  REG_X1,
  REG_X2,
  REG_X3,
  REG_X4,
  REG_X5,
  REG_X6,
  REG_X7,
  REG_X8,
  REG_X9,
  REG_X10,
  REG_X11,
  REG_X12,
  REG_X13,
  REG_X14,
  REG_X15,
  REG_X16,
  REG_X17,
  REG_X18,
  REG_X19,
  REG_X20,
  REG_X21,
  REG_X22,
  REG_X23,
  REG_X24,
  REG_X25,
  REG_X26,
  REG_X27,
  REG_X28,
  REG_X29,
  REG_X30,
  REG_X31,
  REG_FP = REG_X29,
  REG_LR = REG_X30,
  REG_SP = REG_X31
} ARM64RegID;

typedef enum {

  BaseLoadStorePostIdx,
  LoadPostIdx,
  LDRWpost,
  LDRXpost,
  LoadPreIdx,
  LDRWpre,
  LDRXpre,

  LoadLiteral,
  LDRWl,
  LDRXl,

  BaseCmpBranch,
  MULTICLASS(CmpBranch, W),
  MULTICLASS(CBZ, W),
  MULTICLASS(CBNZ, W),
  MULTICLASS(CmpBranch, X),
  MULTICLASS(CBZ, X),
  MULTICLASS(CBNZ, X),

  BranchCond,
  Bcc,

  BaseTestBranch,
  MULTICLASS(TestBranch, W),
  MULTICLASS(TBZ, W),
  MULTICLASS(TBNZ, W),
  MULTICLASS(TestBranch, X),
  MULTICLASS(TBZ, X),
  MULTICLASS(TBNZ, X),

} ARM64InstID;

typedef enum { Invalid, Register, Immediate } OperandType;

typedef struct {
  OperandType type;
  uint8_t start;
  uint8_t len;
} Operand;

typedef struct _ARM64InstructionDecode {
  uint32_t inst;
  ARM64InstID InstID;
} ARM64InstructionDecode;

typedef struct _ARM64Instruction {
  uint32_t dummy0;
  ARM64InstID InstID;
  uint32_t Inst;
  uint32_t Opcode;
  Operand Operands[4];
} ARM64InstructionX;

typedef struct _ARM64Assembler {
  void *dummy;
} ARM64Assembler;

#define BIT32_CONTROL_SET(inst, start, len, bits) inst = (inst | ((bits & ((1 << len) - 1)) << start))
#define BIT32_CONTROL_GET(inst, start, len, bits) bits = ((inst >> start) & ((1 << len) - 1))

uint32_t _BaseLoadStorePostIdx(ARM64InstructionX *inst, uint32_t sz, uint32_t V, uint32_t opc, uint32_t offset, uint32_t Rn,
                               uint32_t Rt);
uint32_t _LoadPostIdx(ARM64InstructionX *inst, uint32_t sz, uint32_t V, uint32_t opc, uint32_t offset, uint32_t Rn,
                      uint32_t Rt);
uint32_t _LDRWpost(ARM64InstructionX *inst, uint32_t offset, uint32_t Rn, uint32_t Rt);

uint32_t _LoadLiteral(ARM64InstructionX *inst, uint32_t opc, uint32_t V, uint32_t Rt, uint32_t label);
uint32_t _LDRWl(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t _LDRXl(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);

uint32_t _BaseCmpBranch(ARM64InstructionX *inst, uint32_t regtype, uint32_t op, uint32_t target, uint32_t Rt);
uint32_t MULTICLASS(_CmpBranch, W)(ARM64InstructionX *inst, uint32_t op, uint32_t target, uint32_t Rt);
uint32_t MULTICLASS(_CBZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t MULTICLASS(_CBNZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t MULTICLASS(_CmpBranch, X)(ARM64InstructionX *inst, uint32_t op, uint32_t target, uint32_t Rt);
uint32_t MULTICLASS(_CBZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t MULTICLASS(_CBNZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);

uint32_t _BranchCond(ARM64InstructionX *inst, uint32_t cond, uint32_t target);
uint32_t _Bcc(ARM64InstructionX *inst, uint32_t cond, uint32_t target);

uint32_t _BaseTestBranch(ARM64InstructionX *inst, uint32_t regtype, uint32_t op, uint32_t bit4, uint32_t target, uint32_t Rt);
uint32_t MULTICLASS(_TestBranch, W)(ARM64InstructionX *inst, uint32_t op, uint32_t bit4, uint32_t target, uint32_t Rt);
uint32_t MULTICLASS(_TBZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t MULTICLASS(_TBNZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t MULTICLASS(_TestBranch, X)(ARM64InstructionX *inst, uint32_t op, uint32_t bit4, uint32_t target, uint32_t Rt);
uint32_t MULTICLASS(_TBZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t MULTICLASS(_TBNZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);

#ifdef __cplusplus
}
#endif

#endif //HOOKZZANDROIDDEMOTEMPLATE_ARM64ASSEMBLER_H
