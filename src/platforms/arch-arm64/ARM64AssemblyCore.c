//
// Created by jmpews on 2018/5/14.
//

#include "ARM64AssemblyCore.h"

uint32_t _BaseLoadStorePostIdx(ARM64InstructionX *inst, uint32_t sz, uint32_t V, uint32_t opc, uint32_t offset, uint32_t Rn,
                               uint32_t Rt) {

  inst->InstID = BaseLoadStorePostIdx;

  uint32_t inst32 = 0;
  BIT32_CONTROL_SET(inst32, 30, 2, sz);
  BIT32_CONTROL_SET(inst32, 27, 3, 0b111);
  BIT32_CONTROL_SET(inst32, 26, 1, V);
  BIT32_CONTROL_SET(inst32, 24, 2, 0b00);
  BIT32_CONTROL_SET(inst32, 22, 2, opc);
  BIT32_CONTROL_SET(inst32, 21, 1, 0b0);
  BIT32_CONTROL_SET(inst32, 12, 9, offset);
  BIT32_CONTROL_SET(inst32, 5, 5, Rn);
  BIT32_CONTROL_SET(inst32, 0, 5, Rt);
  inst->Inst = inst32;

  inst->Operands[0] = (Operand) {Immediate, 12, 9};
  inst->Operands[1] = (Operand) {Register, 5, 5};
  inst->Operands[2] = (Operand) {Register, 0, 5};

  return inst32;
}

uint32_t _LoadPostIdx(ARM64InstructionX *inst, uint32_t sz, uint32_t V, uint32_t opc, uint32_t offset, uint32_t Rn,
                      uint32_t Rt) {

  _BaseLoadStorePostIdx(inst, sz, V, opc, offset, Rn, Rt);
  inst->InstID = LoadPreIdx;
  return inst->Inst;
}

uint32_t _LDRWpost(ARM64InstructionX *inst, uint32_t offset, uint32_t Rn, uint32_t Rt) {
  _LoadPostIdx(inst, 0b10, 0, 0b01, offset, Rn, Rt);
  inst->InstID = LDRWpost;
  return inst->Inst;
}

// ---
// Load literal
// ---
uint32_t _LoadLiteral(ARM64InstructionX *inst, uint32_t opc, uint32_t V, uint32_t Rt, uint32_t label) {

  inst->InstID = LoadLiteral;

  uint32_t inst32 = 0;
  BIT32_CONTROL_SET(inst32, 30, 2, opc);
  BIT32_CONTROL_SET(inst32, 27, 3, 0b011);
  BIT32_CONTROL_SET(inst32, 26, 1, V);
  BIT32_CONTROL_SET(inst32, 24, 2, 0b00);
  BIT32_CONTROL_SET(inst32, 5, 19, label);
  BIT32_CONTROL_SET(inst32, 0, 5, Rt);
  inst->Inst = inst32;

  inst->Operands[0] = (Operand) {Immediate, 5, 19};
  inst->Operands[1] = (Operand) {Register, 0, 5};

  return inst32;
}

uint32_t _LDRWl(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
  _LoadLiteral(inst, 0b00, 0, label, Rt);
  inst->InstID = LDRWl;
  return inst->Inst;
}

uint32_t _LDRXl(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
  _LoadLiteral(inst, 0b01, 0, label, Rt);
  inst->InstID = LDRXl;
  return inst->Inst;
}

//---
// Compare-and-branch ARM64Instructions.
//---

uint32_t _BaseCmpBranch(ARM64InstructionX *inst, uint32_t regtype, uint32_t op, uint32_t target, uint32_t Rt) {
  inst->InstID = BaseCmpBranch;

  uint32_t inst32 = 0;
  BIT32_CONTROL_SET(inst32, 25, 6, 0b011010);
  BIT32_CONTROL_SET(inst32, 24, 1, op);
  BIT32_CONTROL_SET(inst32, 5, 19, target);
  BIT32_CONTROL_SET(inst32, 0, 5, Rt);
  inst->Inst = inst32;

  inst->Operands[0] = (Operand) {Immediate, 5, 19};
  inst->Operands[1] = (Operand) {Register, 0, 5};

  return inst32;
}

uint32_t MULTICLASS(_CmpBranch, W)(ARM64InstructionX *inst, uint32_t op, uint32_t target, uint32_t Rt) {

  _BaseCmpBranch(inst, 0, op, target, Rt);

  BIT32_CONTROL_SET(inst->Inst, 31, 1, TReg32);

  inst->InstID = MULTICLASS(CmpBranch, W);
  return inst->Inst;

}

uint32_t MULTICLASS(_CBZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
  MULTICLASS(_CmpBranch, W)(inst, 0, label, Rt);
  inst->InstID = MULTICLASS(CBZ, W);
  return inst->Inst;
}

uint32_t MULTICLASS(_CBNZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
  MULTICLASS(_CmpBranch, W)(inst, 1, label, Rt);
  inst->InstID = MULTICLASS(CBNZ, W);
  return inst->Inst;
}

uint32_t MULTICLASS(_CmpBranch, X)(ARM64InstructionX *inst, uint32_t op, uint32_t target, uint32_t Rt) {

  _BaseCmpBranch(inst, 0, op, target, Rt);

  BIT32_CONTROL_SET(inst->Inst, 31, 1, TReg64);

  inst->InstID = MULTICLASS(CmpBranch, X);
  return inst->Inst;

}

uint32_t MULTICLASS(_CBZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
  MULTICLASS(_CmpBranch, X)(inst, 0, label, Rt);
  inst->InstID = MULTICLASS(CBZ, X);
  return inst->Inst;
}

uint32_t MULTICLASS(_CBNZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
  MULTICLASS(_CmpBranch, X)(inst, 1, label, Rt);
  inst->InstID = MULTICLASS(CBNZ, X);
  return inst->Inst;
}

//===----------------------------------------------------------------------===//
// Conditional branch (immediate) ARM64InstructionX.
//===----------------------------------------------------------------------===//

uint32_t _BranchCond(ARM64InstructionX *inst, uint32_t cond, uint32_t target) {
  inst->InstID = BranchCond;

  uint32_t inst32 = 0;
  BIT32_CONTROL_SET(inst32, 24, 8, 0b01010100);
  BIT32_CONTROL_SET(inst32, 5, 19, target);
  BIT32_CONTROL_SET(inst32, 4, 1, 0);
  BIT32_CONTROL_SET(inst32, 0, 4, cond);
  inst->Inst = inst32;

  inst->Operands[0] = (Operand) {Immediate, 5, 19};
  inst->Operands[1] = (Operand) {Immediate, 0, 4};

  return inst32;
}

uint32_t _Bcc(ARM64InstructionX *inst, uint32_t cond, uint32_t target) {
  _BranchCond(inst, cond, target);
  inst->InstID = Bcc;
  return inst->InstID;
}

//===----------------------------------------------------------------------===//
// Test-bit-and-branch ARM64Instructions.
//===----------------------------------------------------------------------===//
uint32_t _BaseTestBranch(ARM64InstructionX *inst,
                         uint32_t regtype,
                         uint32_t op,
                         uint32_t bit4,
                         uint32_t target,
                         uint32_t Rt) {
  inst->InstID = BaseTestBranch;
  uint32_t inst32 = 0;
  BIT32_CONTROL_SET(inst32, 25, 6, 0b011011);
  BIT32_CONTROL_SET(inst32, 24, 1, op);
  BIT32_CONTROL_SET(inst32, 19, 4, bit4);
  BIT32_CONTROL_SET(inst32, 5, 14, target);
  BIT32_CONTROL_SET(inst32, 0, 5, Rt);

  inst->Inst = inst32;

  inst->Operands[0] = (Operand) {Immediate, 5, 14};
  inst->Operands[1] = (Operand) {Register, 0, 5};

  return inst32;
}

uint32_t MULTICLASS(_TestBranch, W)(ARM64InstructionX *inst, uint32_t op, uint32_t bit4, uint32_t target, uint32_t Rt) {

  _BaseTestBranch(inst, 0, 0, op, target, Rt);

  BIT32_CONTROL_SET(inst->Inst, 31, 1, TReg32);

  inst->InstID = MULTICLASS(TestBranch, W);
  return inst->Inst;

}

uint32_t MULTICLASS(_TBZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
  MULTICLASS(_CmpBranch, X)(inst, 0, label, Rt);
  inst->InstID = MULTICLASS(TBZ, W);
  return inst->Inst;
}

uint32_t MULTICLASS(_TBNZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
  MULTICLASS(_CmpBranch, X)(inst, 1, label, Rt);
  inst->InstID = MULTICLASS(TBNZ, W);
  return inst->Inst;
}

uint32_t MULTICLASS(_TestBranch, X)(ARM64InstructionX *inst, uint32_t op, uint32_t bit4, uint32_t target, uint32_t Rt) {

  _BaseTestBranch(inst, 0, 0, op, target, Rt);

  BIT32_CONTROL_SET(inst->Inst, 31, 1, TReg64);

  inst->InstID = MULTICLASS(TestBranch, X);
  return inst->Inst;
}

uint32_t MULTICLASS(_TBZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
  MULTICLASS(_CmpBranch, X)(inst, 0, label, Rt);
  inst->InstID = MULTICLASS(TBZ, X);
  return inst->Inst;
}

uint32_t MULTICLASS(_TBNZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
  MULTICLASS(_CmpBranch, X)(inst, 1, label, Rt);
  inst->InstID = MULTICLASS(TBNZ, X);
  return inst->Inst;
}