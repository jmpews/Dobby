//
// Created by jmpews on 2018/5/14.
//

#include "ARM64AssemblyCore.h"

#define INST_FUNC_INITIALIZE(func, ...) func(inst, ##__VA_ARGS__)

// ---
// Load literal
// ---
_LoadLiteral_OOP _LoadLiteral_OOP_LIST[] = {
    LDRWl, 0b00, 0, LDRXl, 0b01, 0,
};

int get_LoadLiteral_OOP(ARM64InstID id, uint32_t opc, uint32_t V) {
    int n = sizeof(_LoadLiteral_OOP_LIST) / sizeof(_LoadLiteral_OOP);
    for (int i = 0; i < n; i++) {
        if (_LoadLiteral_OOP_LIST[i].id == id) {
            return i;
        }
        if (_LoadLiteral_OOP_LIST[i].opc == opc & _LoadLiteral_OOP_LIST[i].V == V) {
            return i;
        }
    }
    return 0;
}
_LoadLiteralType _LoadLiteral(ARM64InstructionX *inst, OperationType optype, int *oppindex, uint32_t *Rt,
                              uint32_t *label) {

    uint32_t inst32 = inst->Inst;
    uint32_t mask32 = 0;
    uint32_t opc = 0, V = 0;
    if (optype == OP_ENCODE) {
        inst->InstID = LoadLiteral;

        BIT32_CONTROL_SET(inst32, 30, 2, _LoadLiteral_OOP_LIST[*oppindex].opc);
        BIT32_CONTROL_MASK_SET(mask32, 30, 2);
        BIT32_CONTROL_SET(inst32, 27, 3, 0b011);
        BIT32_CONTROL_MASK_SET(mask32, 27, 3);
        BIT32_CONTROL_SET(inst32, 26, 1, _LoadLiteral_OOP_LIST[*oppindex].V);
        BIT32_CONTROL_MASK_SET(mask32, 26, 1);
        BIT32_CONTROL_SET(inst32, 24, 2, 0b00);
        BIT32_CONTROL_MASK_SET(mask32, 24, 2);
        BIT32_CONTROL_SET(inst32, 5, 19, *label);
        BIT32_CONTROL_SET(inst32, 0, 5, *Rt);

        inst->Mask = mask32;
        inst->Inst = inst32;
    } else {
        BIT32_CONTROL_GETSET(inst32, 30, 2, opc);
        BIT32_CONTROL_GETSET(inst32, 26, 1, V);
        BIT32_CONTROL_GETSET(inst32, 5, 19, *label);
        BIT32_CONTROL_GETSET(inst32, 0, 5, *Rt);

        get_LoadLiteral_OOP(0, opc, V);

        inst->Operands[0] = (Operand){Immediate, 5, 19, BIT32_CONTROL_GET(inst->Inst, 5, 19)};
        inst->Operands[1] = (Operand){Register, 0, 5, BIT32_CONTROL_GET(inst->Inst, 0, 5)};
    }
    _LoadLiteralType result;
    result.inst  = inst->Inst;
    result.opc   = (OP){opc, 30, 2};
    result.V     = (OP){V, 26, 1};
    result.Rt    = (OP){*Rt, 5, 19};
    result.label = (OP){*label, 0, 5};
    return result;
}

uint32_t _LDRWl(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
    uint32_t opc = 0b00;
    uint32_t V   = 0;
    int index    = get_LoadLiteral_OOP(LDRWl, 0, 0);
    _LoadLiteral(inst, OP_ENCODE, &index, &label, &Rt);
    inst->InstID = LDRWl;
    return inst->Inst;
}

uint32_t _LDRXl(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
    uint32_t opc = 0b01;
    uint32_t V   = 0;
    int index    = get_LoadLiteral_OOP(LDRXl, 0, 0);
    _LoadLiteral(inst, OP_ENCODE, &index, &label, &Rt);
    inst->InstID = LDRXl;
    return inst->Inst;
}

//---
// Compare-and-branch ARM64Instructions.
//---
_BaseCmpBranch_OOP _BaseCmpBranch_OOP_LIST[] = {
    MULTICLASS(CBZ, W), 0, MULTICLASS(CBNZ, W), 1, MULTICLASS(CBZ, X), 0, MULTICLASS(CBNZ, X), 1,
};
_BaseCmpBranchType _BaseCmpBranch(ARM64InstructionX *inst, OperationType optype, uint32_t *op, uint32_t *target,
                                  uint32_t *Rt) {
    uint32_t inst32 = inst->Inst;
    uint32_t mask32 = 0;
    if (optype == OP_ENCODE) {
        inst->InstID = BaseCmpBranch;

        BIT32_CONTROL_SET(inst32, 25, 6, 0b011010);
        BIT32_CONTROL_MASK_SET(mask32, 25, 6);
        BIT32_CONTROL_SET(inst32, 24, 1, *op);
        BIT32_CONTROL_MASK_SET(mask32, 24, 1);
        BIT32_CONTROL_SET(inst32, 5, 19, *target);
        BIT32_CONTROL_SET(inst32, 0, 5, *Rt);

        inst->Mask = mask32;
        inst->Inst = inst32;
    } else {

        BIT32_CONTROL_GETSET(inst32, 24, 1, *op);
        BIT32_CONTROL_GETSET(inst32, 5, 19, *target);
        BIT32_CONTROL_GETSET(inst32, 0, 5, *Rt);
        inst->Operands[0] = (Operand){Immediate, 5, 19, BIT32_CONTROL_GET(inst->Inst, 5, 19)};
        inst->Operands[1] = (Operand){Register, 0, 5, BIT32_CONTROL_GET(inst->Inst, 0, 5)};
    }

    _BaseCmpBranchType result;
    result.inst   = inst->Inst;
    result.op     = (OP){*op, 24, 1};
    result.target = (OP){*target, 5, 19};
    result.Rt     = (OP){*Rt, 0, 5};
    return result;
}

uint32_t MULTICLASS(_CmpBranch, W)(ARM64InstructionX *inst, uint32_t op, uint32_t target, uint32_t Rt) {

    _BaseCmpBranch(inst, OP_ENCODE, &op, &target, &Rt);

    BIT32_CONTROL_SET(inst->Inst, 31, 1, TReg32);

    inst->InstID = MULTICLASS(CmpBranch, W);
    return inst->Inst;
}

// uint32_t MULTICLASS(_CBZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
//     MULTICLASS(_CmpBranch, W)
//     (inst, 0, label, Rt);
//     inst->InstID = MULTICLASS(CBZ, W);
//     return inst->Inst;
// }

// uint32_t MULTICLASS(_CBNZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
//     MULTICLASS(_CmpBranch, W)
//     (inst, 1, label, Rt);
//     inst->InstID = MULTICLASS(CBNZ, W);
//     return inst->Inst;
// }

uint32_t MULTICLASS(_CmpBranch, X)(ARM64InstructionX *inst, uint32_t op, uint32_t target, uint32_t Rt) {

    _BaseCmpBranch(inst, OP_ENCODE, &op, &target, &Rt);

    BIT32_CONTROL_SET(inst->Inst, 31, 1, TReg64);

    inst->InstID = MULTICLASS(CmpBranch, X);
    return inst->Inst;
}

// uint32_t MULTICLASS(_CBZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
//     MULTICLASS(_CmpBranch, X)
//     (inst, 0, label, Rt);
//     inst->InstID = MULTICLASS(CBZ, X);
//     return inst->Inst;
// }

// uint32_t MULTICLASS(_CBNZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
//     MULTICLASS(_CmpBranch, X)
//     (inst, 1, label, Rt);
//     inst->InstID = MULTICLASS(CBNZ, X);
//     return inst->Inst;
// }

//===----------------------------------------------------------------------===//
// Conditional branch (immediate) ARM64InstructionX.
//===----------------------------------------------------------------------===//
_BranchCond_OOP _BranchCond_OOP_LIST[] = {Bcc};
_BranchCondType _BranchCond(ARM64InstructionX *inst, OperationType optype, uint32_t *cond, uint32_t *target) {

    uint32_t inst32 = inst->Inst;
    uint32_t mask32 = 0;

    if (optype == OP_ENCODE) {
        inst->InstID = BranchCond;

        BIT32_CONTROL_SET(inst32, 24, 8, 0b01010100);
        BIT32_CONTROL_MASK_SET(mask32, 24, 8);
        BIT32_CONTROL_SET(inst32, 5, 19, *target);
        BIT32_CONTROL_SET(inst32, 4, 1, 0);
        BIT32_CONTROL_MASK_SET(mask32, 4, 1);
        BIT32_CONTROL_SET(inst32, 0, 4, *cond);

        inst->Mask = mask32;
        inst->Inst = inst32;
    } else {
        BIT32_CONTROL_GETSET(inst32, 5, 19, *target);
        BIT32_CONTROL_GETSET(inst32, 0, 4, *cond);

        inst->Operands[0] = (Operand){Immediate, 5, 19, BIT32_CONTROL_GET(inst->Inst, 5, 19)};
        inst->Operands[1] = (Operand){Immediate, 0, 4, BIT32_CONTROL_GET(inst->Inst, 0, 4)};
    }
    _BranchCondType result;
    result.inst   = inst->Inst;
    result.target = (OP){*target, 5, 19};
    result.cond   = (OP){*cond, 0, 4};
    return result;
}

uint32_t _Bcc(ARM64InstructionX *inst, uint32_t cond, uint32_t target) {
    _BranchCond(inst, OP_ENCODE, &cond, &target);
    inst->InstID = Bcc;
    return inst->Inst;
}

//===----------------------------------------------------------------------===//
// Test-bit-and-branch ARM64Instructions.
//===----------------------------------------------------------------------===//
_BaseTestBranch_OOP _BaseTestBranch_OOP_LIST[] = {MULTICLASS(TBZ, W), 0, MULTICLASS(TBNZ, W), 1,
                                                  MULTICLASS(TBZ, X), 0, MULTICLASS(TBNZ, X), 1};
_BaseTestBranchType _BaseTestBranch(ARM64InstructionX *inst, OperationType optype, uint32_t *op, uint32_t *bit_19_4,
                                    uint32_t *target, uint32_t *Rt) {
    uint32_t inst32 = inst->Inst;
    uint32_t mask32 = 0;
    if (optype == OP_ENCODE) {

        inst->InstID = BaseTestBranch;
        BIT32_CONTROL_SET(inst32, 25, 6, 0b011011);
        BIT32_CONTROL_MASK_SET(mask32, 25, 6);
        BIT32_CONTROL_SET(inst32, 24, 1, *op);
        BIT32_CONTROL_MASK_SET(mask32, 24, 1);
        BIT32_CONTROL_SET(inst32, 19, 4, *bit_19_4);
        BIT32_CONTROL_SET(inst32, 5, 14, *target);
        BIT32_CONTROL_SET(inst32, 0, 5, *Rt);

        inst->Mask = mask32;
        inst->Inst = inst32;
    } else {

        BIT32_CONTROL_GETSET(inst32, 24, 1, *op);
        BIT32_CONTROL_GETSET(inst32, 19, 4, *bit_19_4);
        BIT32_CONTROL_GETSET(inst32, 5, 14, *target);
        BIT32_CONTROL_GETSET(inst32, 0, 5, *Rt);

        inst->Operands[0] = (Operand){Immediate, 5, 14, BIT32_CONTROL_GET(inst->Inst, 5, 19)};
        inst->Operands[1] = (Operand){Register, 0, 5, BIT32_CONTROL_GET(inst->Inst, 0, 5)};
    }

    _BaseTestBranchType result;
    result.inst     = inst->Inst;
    result.op       = (OP){*op, 24, 1};
    result.bit_19_4 = (OP){*bit_19_4, 19, 4};
    result.target   = (OP){*target, 5, 14};
    result.Rt       = (OP){*Rt, 0, 5};
    return result;
}

uint32_t MULTICLASS(_TestBranch, W)(ARM64InstructionX *inst, uint32_t op, uint32_t bit4, uint32_t target, uint32_t Rt) {

    _BaseTestBranch(inst, OP_ENCODE, 0, &op, &target, &Rt);

    BIT32_CONTROL_SET(inst->Inst, 31, 1, TReg32);

    inst->InstID = MULTICLASS(TestBranch, W);
    return inst->Inst;
}

// uint32_t MULTICLASS(_TBZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
//     MULTICLASS(_CmpBranch, W)
//     (inst, 0, label, Rt);
//     inst->InstID = MULTICLASS(TBZ, W);
//     return inst->Inst;
// }

// uint32_t MULTICLASS(_TBNZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
//     MULTICLASS(_CmpBranch, W)
//     (inst, 1, label, Rt);
//     inst->InstID = MULTICLASS(TBNZ, W);
//     return inst->Inst;
// }

uint32_t MULTICLASS(_TestBranch, X)(ARM64InstructionX *inst, uint32_t op, uint32_t bit4, uint32_t target, uint32_t Rt) {

    _BaseTestBranch(inst, OP_ENCODE, 0, &op, &target, &Rt);

    BIT32_CONTROL_SET(inst->Inst, 31, 1, TReg64);

    inst->InstID = MULTICLASS(TestBranch, X);
    return inst->Inst;
}

// uint32_t MULTICLASS(_TBZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
//     MULTICLASS(_CmpBranch, X)
//     (inst, 0, label, Rt);
//     inst->InstID = MULTICLASS(TBZ, X);
//     return inst->Inst;
// }

// uint32_t MULTICLASS(_TBNZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt) {
//     MULTICLASS(_CmpBranch, X)
//     (inst, 1, label, Rt);
//     inst->InstID = MULTICLASS(TBNZ, X);
//     return inst->Inst;
// }

//===----------------------------------------------------------------------===//
// Unconditional branch (immediate) instructions.
//===----------------------------------------------------------------------===//
_BImm_OOP _BImm_OOP_LIST[] = {B, 0, BL, 1};
_BImmType _BImm(ARM64InstructionX *inst, OperationType optype, uint32_t *op, uint32_t *addr) {
    uint32_t inst32 = inst->Inst;
    uint32_t mask32 = 0;
    if (optype == OP_ENCODE) {

        inst->InstID = BImm;
        BIT32_CONTROL_SET(inst32, 31, 1, *op);
        BIT32_CONTROL_MASK_SET(mask32, 31, 1);
        BIT32_CONTROL_SET(inst32, 26, 5, 0b00101);
        BIT32_CONTROL_MASK_SET(mask32, 26, 5);
        BIT32_CONTROL_SET(inst32, 0, 26, *addr);

        inst->Mask = mask32;
        inst->Inst = inst32;
    } else {

        BIT32_CONTROL_GETSET(inst32, 31, 1, *op);
        BIT32_CONTROL_GETSET(inst32, 0, 26, *addr);

        inst->Operands[0] = (Operand){Immediate, 0, 26, BIT32_CONTROL_GET(inst->Inst, 0, 26)};
    }

    _BImmType result;
    result.inst = inst->Inst;
    result.op   = (OP){*op, 31, 1};
    result.addr = (OP){*addr, 0, 26};
    return result;
}
uint32_t _BranchImm(ARM64InstructionX *inst, uint32_t op, uint32_t addr) {
    _BImm(inst, OP_ENCODE, &op, &addr);
    inst->InstID = BranchImm;
    return inst->Inst;
}
uint32_t _B(ARM64InstructionX *inst, uint32_t addr) {
    uint32_t op = 0;
    _BranchImm(inst, op, addr);
    inst->InstID = B;
    return inst->Inst;
}
uint32_t _CallImm(ARM64InstructionX *inst, uint32_t op, uint32_t addr) {
    _BImm(inst, OP_ENCODE, &op, &addr);
    inst->InstID = CallImm;
    return inst->Inst;
}
uint32_t _BL(ARM64InstructionX *inst, uint32_t addr) {
    uint32_t op = 1;
    _CallImm(inst, op, addr);
    inst->InstID = BL;
    return inst->Inst;
}

ARM64InstructionID ARM64InstructionIDTable[256] = {0};

__attribute__((constructor)) void initializeARM64InstructionIDTable() {
    ARM64InstructionX inst;
    int i, n = 0;
    uint32_t v0 = 0;

    n = sizeof(_LoadLiteral_OOP_LIST) / sizeof(_LoadLiteral_OOP);
    for (int i = 0; i < n; i++) {
        _LoadLiteral(&inst, OP_ENCODE, &i, &v0, &v0);
        ARM64InstructionIDTable[i++] = (ARM64InstructionID){inst.Inst, inst.Mask, inst.InstID};
    }

    n = sizeof(_BaseCmpBranch_OOP_LIST) / sizeof(_BaseCmpBranch_OOP);
    for (int i = 0; i < n; i++) {
        _BaseCmpBranch(&inst, OP_ENCODE, &_BaseCmpBranch_OOP_LIST[i].op, &v0, &v0);
        ARM64InstructionIDTable[i++] = (ARM64InstructionID){inst.Inst, inst.Mask, inst.InstID};
    }

    _BranchCond(&inst, OP_ENCODE, &v0, &v0);
    ARM64InstructionIDTable[i++] = (ARM64InstructionID){inst.Inst, inst.Mask, inst.InstID};

    n = sizeof(_BaseTestBranch_OOP_LIST) / sizeof(_BaseTestBranch_OOP);
    for (int i = 0; i < n; i++) {
        _BaseTestBranch(&inst, OP_ENCODE, &_BaseTestBranch_OOP_LIST[i].op, &v0, &v0, &v0);
        ARM64InstructionIDTable[i++] = (ARM64InstructionID){inst.Inst, inst.Mask, inst.InstID};
    }

    _B(&inst, 0);
    ARM64InstructionIDTable[i++] = (ARM64InstructionID){inst.Inst, inst.Mask, inst.InstID};

    _BL(&inst, 0);
    ARM64InstructionIDTable[i++] = (ARM64InstructionID){inst.Inst, inst.Mask, inst.InstID};
}