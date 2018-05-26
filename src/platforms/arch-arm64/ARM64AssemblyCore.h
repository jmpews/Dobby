//
// Created by z on 2018/5/7.
//

#ifndef HOOKZZANDROIDDEMOTEMPLATE_ARM64ASSEMBLER_H
#define HOOKZZANDROIDDEMOTEMPLATE_ARM64ASSEMBLER_H

#include <stdarg.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ARM64InstructionX ARM64InstructionX

#define MULTICLASS(parent, child) parent##_##child

typedef enum { DECODE, ENCODE, INIT } OperationType;

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
} ARM64InstructionX;

inline void BIT32SET(uint32_t *inst32, int start, int len, uint32_t v) {
    if (!inst32)
        return;
    *inst32 = *inst32 | (v << start);
    // *inst32 = (*inst32 & ~(((1 << len) - 1) << start)) | (v << start);
}

inline void BIT32SETMASK(uint32_t *inst32, int start, int len) {
    if (!inst32)
        return;
    *inst32 = *inst32 | (((1 << len) - 1) << start);
}
inline void BIT32MASKSET(uint32_t *inst32, uint32_t *mask32, int start, int len, uint32_t v) {
    if (!inst32)
        return;
    *inst32 = *inst32 | (v << start);
    *mask32 = *mask32 | (((1 << len) - 1) << start);
}

inline void BIT32GET(uint32_t inst32, int start, int len, uint32_t *v) {
    if (!v)
        return;
    *v = (inst32 >> start) & ((1 << len) - 1);
}

void ARM64CoreINIT(ARM64InstId id);
ARM64InstId getInstType(uint32_t inst32);

#ifdef __cplusplus
}
#endif

#endif //HOOKZZANDROIDDEMOTEMPLATE_ARM64ASSEMBLER_H
