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
} ARM64InstId;

typedef enum { Invalid, Register, Immediate } OperandType;

typedef struct {
    // uint32_t op;
    uint16_t op_start;
    uint16_t op_len;
} OP;

typedef struct _ARM64InstructionX {
    ARM64InstId id;
    int isClass; // 暂时不分成两个数组, 仅通过 isClass 区分
    int parentIndex;
    uint32_t inst32;
    uint32_t mask32;
    int opCount;
    uintptr_t opIndex;
} ARM64InstructionX;

#define BIT32_CONTROL_MASK_SET(inst, start, len) inst = (inst | (((1 << len) - 1) << start))
#define BIT32_CONTROL_SET(inst, start, len, bits) inst = ((inst & ~(((1 << len) - 1) << start)) | (bits << start))
#define BIT32_CONTROL_GETSET(inst, start, len, bits) bits = ((inst >> start) & ((1 << len) - 1))
#define BIT32_CONTROL_GET(inst, start, len) ((inst >> start) & ((1 << len) - 1))

#ifdef __cplusplus
}
#endif

#endif //HOOKZZANDROIDDEMOTEMPLATE_ARM64ASSEMBLER_H
