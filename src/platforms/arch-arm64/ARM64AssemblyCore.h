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

typedef enum { OP_DECODE, OP_ENCODE } OperationType;

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

    BImm,
    BranchImm,
    B,
    CallImm,
    BL,

    UNKNOWN
} ARM64InstID;

typedef enum { Invalid, Register, Immediate } OperandType;

typedef struct {
    uint32_t op;
    uint16_t op_start;
    uint16_t op_len;
} OP;

typedef struct {
    OperandType type;
    uint8_t start;
    uint8_t len;
    uint32_t value;
} Operand;

typedef struct _ARM64InstructionID {
    uint32_t inst;
    ARM64InstID InstID;
} ARM64InstructionID;

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

#define BIT32_CONTROL_SET(inst, start, len, bits) inst = (inst & ~(((1 << len) - 1) << start) | (bits << start))
#define BIT32_CONTROL_GETSET(inst, start, len, bits) bits = ((inst >> start) & ((1 << len) - 1))
#define BIT32_CONTROL_GET(inst, start, len) ((inst >> start) & ((1 << len) - 1))

uint32_t _BaseLoadStorePostIdx(ARM64InstructionX *inst, uint32_t sz, uint32_t V, uint32_t opc, uint32_t offset,
                               uint32_t Rn, uint32_t Rt);
uint32_t _LoadPostIdx(ARM64InstructionX *inst, uint32_t sz, uint32_t V, uint32_t opc, uint32_t offset, uint32_t Rn,
                      uint32_t Rt);
uint32_t _LDRWpost(ARM64InstructionX *inst, uint32_t offset, uint32_t Rn, uint32_t Rt);

typedef struct {
    uint32_t inst;
    OP opc;
    OP V;
    OP Rt;
    OP label;
} _LoadLiteralType;
_LoadLiteralType _LoadLiteral(ARM64InstructionX *inst, OperationType optype, uint32_t *opc, uint32_t *V, uint32_t *Rt,
                              uint32_t *label);
uint32_t _LDRWl(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t _LDRXl(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);

typedef struct {
    uint32_t inst;
    OP op;
    OP target;
    OP Rt;
} _BaseCmpBranchType;
_BaseCmpBranchType _BaseCmpBranch(ARM64InstructionX *inst, OperationType optype, uint32_t *op, uint32_t *target,
                                  uint32_t *Rt);
uint32_t MULTICLASS(_CmpBranch, W)(ARM64InstructionX *inst, uint32_t op, uint32_t target, uint32_t Rt);
uint32_t MULTICLASS(_CBZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t MULTICLASS(_CBNZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t MULTICLASS(_CmpBranch, X)(ARM64InstructionX *inst, uint32_t op, uint32_t target, uint32_t Rt);
uint32_t MULTICLASS(_CBZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t MULTICLASS(_CBNZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);

typedef struct {
    uint32_t inst;
    OP cond;
    OP target;
} _BranchCondType;
_BranchCondType _BranchCond(ARM64InstructionX *inst, OperationType optype, uint32_t *cond, uint32_t *target);
uint32_t _Bcc(ARM64InstructionX *inst, uint32_t cond, uint32_t target);

typedef struct {
    uint32_t inst;
    OP op;
    OP bit_19_4;
    OP target;
    OP Rt;
} _BaseTestBranchType;
_BaseTestBranchType _BaseTestBranch(ARM64InstructionX *inst, OperationType optype, uint32_t *op, uint32_t *bit_19_4,
                                    uint32_t *target, uint32_t *Rt);
uint32_t MULTICLASS(_TestBranch, W)(ARM64InstructionX *inst, uint32_t op, uint32_t bit4, uint32_t target, uint32_t Rt);
uint32_t MULTICLASS(_TBZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t MULTICLASS(_TBNZ, W)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t MULTICLASS(_TestBranch, X)(ARM64InstructionX *inst, uint32_t op, uint32_t bit4, uint32_t target, uint32_t Rt);
uint32_t MULTICLASS(_TBZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);
uint32_t MULTICLASS(_TBNZ, X)(ARM64InstructionX *inst, uint32_t label, uint32_t Rt);

typedef struct {
    uint32_t inst;
    OP op;
    OP addr;
} _BImmType;
_BImmType _BImm(ARM64InstructionX *inst, OperationType optype, uint32_t *op, uint32_t *addr);
uint32_t _BranchImm(ARM64InstructionX *inst, uint32_t op, uint32_t addr);
uint32_t _B(ARM64InstructionX *inst, uint32_t addr);
uint32_t _CallImm(ARM64InstructionX *inst, uint32_t op, uint32_t addr);
uint32_t _BL(ARM64InstructionX *inst, uint32_t addr);

#ifdef __cplusplus
}
#endif

#endif //HOOKZZANDROIDDEMOTEMPLATE_ARM64ASSEMBLER_H
