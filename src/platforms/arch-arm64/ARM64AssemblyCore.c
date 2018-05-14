//
// Created by jmpews on 2018/5/14.
//

#include "ARM64AssemblyCore.h"

#define INST_FUNC_INITIALIZE(func, ...) func(inst, ##__VA_ARGS__)

uint32_t _BaseLoadStorePostIdx(ARM64InstructionX *inst, uint32_t sz, uint32_t V, uint32_t opc, uint32_t offset,
                               uint32_t Rn, uint32_t Rt)
{

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

    inst->Operands[0] = (Operand){Immediate, 12, 9};
    inst->Operands[1] = (Operand){Register, 5, 5};
    inst->Operands[2] = (Operand){Register, 0, 5};

    return inst32;
}

uint32_t _LoadPostIdx(ARM64InstructionX *inst, uint32_t sz, uint32_t V, uint32_t opc, uint32_t offset, uint32_t Rn,
                      uint32_t Rt)
{

    _BaseLoadStorePostIdx(inst, sz, V, opc, offset, Rn, Rt);
    inst->InstID = LoadPreIdx;
    return inst->Inst;
}

uint32_t _LDRWpost(ARM64InstructionX *inst, uint32_t offset, uint32_t Rn, uint32_t Rt)
{
    _LoadPostIdx(inst, 0b10, 0, 0b01, offset, Rn, Rt);
    inst->InstID = LDRWpost;
    return inst->Inst;
}

// ---
// Load literal
// ---
_LoadLiteralType _LoadLiteral(ARM64InstructionX *inst, OperationType optype, uint32_t *opc, uint32_t *V, uint32_t *Rt,
                              uint32_t *label)
{

    uint32_t inst32 = inst->Inst;
    if (optype == OP_ENCODE)
    {
        inst->InstID = LoadLiteral;

        BIT32_CONTROL_SET(inst32, 30, 2, *opc);
        BIT32_CONTROL_SET(inst32, 27, 3, 0b011);
        BIT32_CONTROL_SET(inst32, 26, 1, *V);
        BIT32_CONTROL_SET(inst32, 24, 2, 0b00);
        BIT32_CONTROL_SET(inst32, 5, 19, *label);
        BIT32_CONTROL_SET(inst32, 0, 5, *Rt);
        inst->Inst = inst32;
    }
    else
    {
        BIT32_CONTROL_GETSET(inst32, 30, 2, *opc);
        BIT32_CONTROL_SET(inst32, 27, 3, 0b011);
        BIT32_CONTROL_GETSET(inst32, 26, 1, *V);
        BIT32_CONTROL_SET(inst32, 24, 2, 0b00);
        BIT32_CONTROL_GETSET(inst32, 5, 19, *label);
        BIT32_CONTROL_GETSET(inst32, 0, 5, *Rt);

        inst->Operands[0] = (Operand){Immediate, 5, 19, BIT32_CONTROL_GET(inst->Inst, 5, 19)};
        inst->Operands[1] = (Operand){Register, 0, 5, BIT32_CONTROL_GET(inst->Inst, 0, 5)};
    }
    _LoadLiteralType result;
    result.inst = inst->Inst;
    result.opc = (OP){*opc, 30, 2};
    result.V = (OP){*V, 26, 1};
    result.Rt = (OP){*Rt, 5, 19};
    result.label = (OP){*label, 0, 5};
    return result;
}

uint32_t _LDRWl(ARM64InstructionX *inst, uint32_t label, uint32_t Rt)
{
    uint32_t opc = 0b00;
    uint32_t V = 0;
    _LoadLiteral(inst, OP_ENCODE, &opc, &V, &label, &Rt);
    inst->InstID = LDRWl;
    return inst->Inst;
}

uint32_t _LDRXl(ARM64InstructionX *inst, uint32_t label, uint32_t Rt)
{
    uint32_t opc = 0b01;
    uint32_t V = 0;
    _LoadLiteral(inst, OP_ENCODE, &opc, &V, &label, &Rt);
    inst->InstID = LDRXl;
    return inst->Inst;
}

//---
// Compare-and-branch ARM64Instructions.
//---

_BaseCmpBranchType _BaseCmpBranch(ARM64InstructionX *inst, OperationType optype, uint32_t *op, uint32_t *target,
                                  uint32_t *Rt)
{
    uint32_t inst32 = inst->Inst;
    if (optype == OP_ENCODE)
    {
        inst->InstID = BaseCmpBranch;

        BIT32_CONTROL_SET(inst32, 25, 6, 0b011010);
        BIT32_CONTROL_SET(inst32, 24, 1, *op);
        BIT32_CONTROL_SET(inst32, 5, 19, *target);
        BIT32_CONTROL_SET(inst32, 0, 5, *Rt);
        inst->Inst = inst32;
    }
    else
    {

        BIT32_CONTROL_SET(inst32, 25, 6, 0b011010);
        BIT32_CONTROL_GETSET(inst32, 24, 1, *op);
        BIT32_CONTROL_GETSET(inst32, 5, 19, *target);
        BIT32_CONTROL_GETSET(inst32, 0, 5, *Rt);
        inst->Operands[0] = (Operand){Immediate, 5, 19, BIT32_CONTROL_GET(inst->Inst, 5, 19)};
        inst->Operands[1] = (Operand){Register, 0, 5, BIT32_CONTROL_GET(inst->Inst, 0, 5)};
    }

    _BaseCmpBranchType result;
    result.inst = inst->Inst;
    result.op = (OP){*op, 24, 1};
    result.target = (OP){*target, 5, 19};
    result.Rt = (OP){*Rt, 0, 5};
    return result;
}

uint32_t MULTICLASS(_CmpBranch, W)(ARM64InstructionX *inst, uint32_t op, uint32_t target, uint32_t Rt)
{

    _BaseCmpBranch(inst, OP_ENCODE, &op, &target, &Rt);

    BIT32_CONTROL_SET(inst->Inst, 31, 1, TReg32);

    inst->InstID = MULTICLASS(CmpBranch, W);
    return inst->Inst;
}

uint32_t MULTICLASS(_CBZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt)
{
    MULTICLASS(_CmpBranch, W)
    (inst, 0, label, Rt);
    inst->InstID = MULTICLASS(CBZ, W);
    return inst->Inst;
}

uint32_t MULTICLASS(_CBNZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt)
{
    MULTICLASS(_CmpBranch, W)
    (inst, 1, label, Rt);
    inst->InstID = MULTICLASS(CBNZ, W);
    return inst->Inst;
}

uint32_t MULTICLASS(_CmpBranch, X)(ARM64InstructionX *inst, uint32_t op, uint32_t target, uint32_t Rt)
{

    _BaseCmpBranch(inst, OP_ENCODE, &op, &target, &Rt);

    BIT32_CONTROL_SET(inst->Inst, 31, 1, TReg64);

    inst->InstID = MULTICLASS(CmpBranch, X);
    return inst->Inst;
}

uint32_t MULTICLASS(_CBZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt)
{
    MULTICLASS(_CmpBranch, X)
    (inst, 0, label, Rt);
    inst->InstID = MULTICLASS(CBZ, X);
    return inst->Inst;
}

uint32_t MULTICLASS(_CBNZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt)
{
    MULTICLASS(_CmpBranch, X)
    (inst, 1, label, Rt);
    inst->InstID = MULTICLASS(CBNZ, X);
    return inst->Inst;
}

//===----------------------------------------------------------------------===//
// Conditional branch (immediate) ARM64InstructionX.
//===----------------------------------------------------------------------===//

_BranchCondType _BranchCond(ARM64InstructionX *inst, OperationType optype, uint32_t *cond, uint32_t *target)
{

    uint32_t inst32 = inst->Inst;
    if (optype == OP_ENCODE)
    {
        inst->InstID = BranchCond;

        BIT32_CONTROL_SET(inst32, 24, 8, 0b01010100);
        BIT32_CONTROL_SET(inst32, 5, 19, *target);
        BIT32_CONTROL_SET(inst32, 4, 1, 0);
        BIT32_CONTROL_SET(inst32, 0, 4, *cond);
        inst->Inst = inst32;
    }
    else
    {

        BIT32_CONTROL_SET(inst32, 24, 8, 0b01010100);
        BIT32_CONTROL_GETSET(inst32, 5, 19, *target);
        BIT32_CONTROL_SET(inst32, 4, 1, 0);
        BIT32_CONTROL_GETSET(inst32, 0, 4, *cond);
        inst->Inst = inst32;

        inst->Operands[0] = (Operand){Immediate, 5, 19, BIT32_CONTROL_GET(inst->Inst, 5, 19)};
        inst->Operands[1] = (Operand){Immediate, 0, 4, BIT32_CONTROL_GET(inst->Inst, 0, 4)};
    }
    _BranchCondType result;
    result.inst = inst->Inst;
    result.target = (OP){*target, 5, 19};
    result.cond = (OP){*cond, 0, 4};
    return result;
}

uint32_t _Bcc(ARM64InstructionX *inst, uint32_t cond, uint32_t target)
{
    _BranchCond(inst, OP_ENCODE, &cond, &target);
    inst->InstID = Bcc;
    return inst->Inst;
}

//===----------------------------------------------------------------------===//
// Test-bit-and-branch ARM64Instructions.
//===----------------------------------------------------------------------===//
_BaseTestBranchType _BaseTestBranch(ARM64InstructionX *inst, OperationType optype, uint32_t *op, uint32_t *bit_19_4,
                                    uint32_t *target, uint32_t *Rt)
{
    uint32_t inst32 = inst->Inst;
    if (optype == OP_ENCODE)
    {

        inst->InstID = BaseTestBranch;
        BIT32_CONTROL_SET(inst32, 25, 6, 0b011011);
        BIT32_CONTROL_SET(inst32, 24, 1, *op);
        BIT32_CONTROL_SET(inst32, 19, 4, *bit_19_4);
        BIT32_CONTROL_SET(inst32, 5, 14, *target);
        BIT32_CONTROL_SET(inst32, 0, 5, *Rt);

        inst->Inst = inst32;
    }
    else
    {

        BIT32_CONTROL_SET(inst32, 25, 6, 0b011011);
        BIT32_CONTROL_GETSET(inst32, 24, 1, *op);
        BIT32_CONTROL_GETSET(inst32, 19, 4, *bit_19_4);
        BIT32_CONTROL_GETSET(inst32, 5, 14, *target);
        BIT32_CONTROL_GETSET(inst32, 0, 5, *Rt);

        inst->Operands[0] = (Operand){Immediate, 5, 14, BIT32_CONTROL_GET(inst->Inst, 5, 19)};
        inst->Operands[1] = (Operand){Register, 0, 5, BIT32_CONTROL_GET(inst->Inst, 0, 5)};
    }

    _BaseTestBranchType result;
    result.inst = inst->Inst;
    result.op = (OP){*op, 24, 1};
    result.bit_19_4 = (OP){*bit_19_4, 19, 4};
    result.target = (OP){*target, 5, 14};
    result.Rt = (OP){*Rt, 0, 5};
    return result;
}

uint32_t MULTICLASS(_TestBranch, W)(ARM64InstructionX *inst, uint32_t op, uint32_t bit4, uint32_t target, uint32_t Rt)
{

    _BaseTestBranch(inst, OP_ENCODE, 0, &op, &target, &Rt);

    BIT32_CONTROL_SET(inst->Inst, 31, 1, TReg32);

    inst->InstID = MULTICLASS(TestBranch, W);
    return inst->Inst;
}

uint32_t MULTICLASS(_TBZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt)
{
    MULTICLASS(_CmpBranch, W)
    (inst, 0, label, Rt);
    inst->InstID = MULTICLASS(TBZ, W);
    return inst->Inst;
}

uint32_t MULTICLASS(_TBNZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt)
{
    MULTICLASS(_CmpBranch, W)
    (inst, 1, label, Rt);
    inst->InstID = MULTICLASS(TBNZ, W);
    return inst->Inst;
}

uint32_t MULTICLASS(_TestBranch, X)(ARM64InstructionX *inst, uint32_t op, uint32_t bit4, uint32_t target, uint32_t Rt)
{

    _BaseTestBranch(inst, OP_ENCODE, 0, &op, &target, &Rt);

    BIT32_CONTROL_SET(inst->Inst, 31, 1, TReg64);

    inst->InstID = MULTICLASS(TestBranch, X);
    return inst->Inst;
}

uint32_t MULTICLASS(_TBZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt)
{
    MULTICLASS(_CmpBranch, X)
    (inst, 0, label, Rt);
    inst->InstID = MULTICLASS(TBZ, X);
    return inst->Inst;
}

uint32_t MULTICLASS(_TBNZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt)
{
    MULTICLASS(_CmpBranch, X)
    (inst, 1, label, Rt);
    inst->InstID = MULTICLASS(TBNZ, X);
    return inst->Inst;
}

//===----------------------------------------------------------------------===//
// Unconditional branch (immediate) instructions.
//===----------------------------------------------------------------------===//

_BImmType _BImm(ARM64InstructionX *inst, OperationType optype, uint32_t *op, uint32_t *addr)
{
    uint32_t inst32 = inst->Inst;
    if (optype == OP_ENCODE)
    {

        inst->InstID = BImm;
        BIT32_CONTROL_SET(inst32, 31, 1, *op);
        BIT32_CONTROL_SET(inst32, 26, 5, 0b00101);
        BIT32_CONTROL_SET(inst32, 0, 26, *addr);

        inst->Inst = inst32;
    }
    else
    {

        BIT32_CONTROL_GETSET(inst32, 31, 1, *op);
        BIT32_CONTROL_SET(inst32, 26, 5, 0b00101);
        BIT32_CONTROL_GETSET(inst32, 0, 26, *addr);

        inst->Operands[0] = (Operand){Immediate, 0, 26, BIT32_CONTROL_GET(inst->Inst, 0, 26)};
    }

    _BImmType result;
    result.inst = inst->Inst;
    result.op = (OP){*op, 31, 1};
    result.addr = (OP){*addr, 0, 26};
    return result;
}
uint32_t _BranchImm(ARM64InstructionX *inst, uint32_t op, uint32_t addr)
{
    _BImm(inst, OP_ENCODE, &op, &addr);
    inst->InstID = BranchImm;
    return inst->Inst;
}
uint32_t _B(ARM64InstructionX *inst, uint32_t addr)
{
    uint32_t op = 0;
    _BranchImm(inst, op, addr);
    inst->InstID = B;
    return inst->Inst;
}
uint32_t _CallImm(ARM64InstructionX *inst, uint32_t op, uint32_t addr)
{
    _BImm(inst, OP_ENCODE, &op, &addr);
    inst->InstID = CallImm;
    return inst->Inst;
}
uint32_t _BL(ARM64InstructionX *inst, uint32_t addr)
{
    uint32_t op = 1;
    _CallImm(inst, op, addr);
    inst->InstID = BL;
    return inst->Inst;
}

ARM64InstructionID ARM64InstructionIDTable[256];

__attribute__((constructor)) void initializeARM64InstructionIDTable()
{
    ARM64InstructionX inst;
    int i = 0;
    uint32_t v0 = 0;

    _LoadLiteral(&inst, OP_ENCODE, &v0, &v0, &v0, &v0);
    ARM64InstructionIDTable[i++] = (ARM64InstructionID){inst.Inst, inst.InstID};

    _BaseCmpBranch(&inst, OP_ENCODE, &v0, &v0, &v0);
    ARM64InstructionIDTable[i++] = (ARM64InstructionID){inst.Inst, inst.InstID};

    _BranchCond(&inst, OP_ENCODE, &v0, &v0);
    ARM64InstructionIDTable[i++] = (ARM64InstructionID){inst.Inst, inst.InstID};

    _BaseTestBranch(&inst, OP_ENCODE, &v0, &v0, &v0, &v0);
    ARM64InstructionIDTable[i++] = (ARM64InstructionID){inst.Inst, inst.InstID};

    _B(&inst, 0);
    ARM64InstructionIDTable[i++] = (ARM64InstructionID){inst.Inst, inst.InstID};

    _BL(&inst, 0);
    ARM64InstructionIDTable[i++] = (ARM64InstructionID){inst.Inst, inst.InstID};
}