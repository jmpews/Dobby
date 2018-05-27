//
// Created by jmpews on 2018/5/14.
//

#include "ARM64AssemblyCore.h"

#define INST_FUNC_INITIALIZE(func, ...) func(inst, ##__VA_ARGS__)
#define WORD_SIZE 8

inline void BIT32SET(uint32_t *inst32, int start, int len, uint32_t v) {
    if (!inst32)
        return;
    // *inst32 = *inst32 | (v << start);
    *inst32 = (*inst32 & ~(((1 << len) - 1) << start)) | (v << start);
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

#if 0
void ARM64CoreINIT(ARM64InstId id) {
    ARM64InstructionX *instX = (ARM64InstructionX *)((uintptr_t)ARM64InstArrary + (int)id * sizeof(ARM64InstructionX));
    int parentId             = -1;
    uint32_t bits[4 * WORD_SIZE] = {0}; // trick :) AKA LLVM bits<>

    do {
        switch (id) {
        case LDRWl:
            parentId = LoadLiteral;
            bits[30] = 0b00; // opc
            BIT32SETMASK(&instX->mask32, 30, 2);
            bits[26] = 0; // V
            BIT32SETMASK(&instX->mask32, 26, 1);
            break;
        case LDRXl:
            parentId = LoadLiteral;
            bits[30] = 0b01; // opc
            BIT32SETMASK(&instX->mask32, 30, 2);
            bits[26] = 0; // V
            BIT32SETMASK(&instX->mask32, 26, 1);
            break;
        case LoadLiteral:
            parentId = ARM64_INST_END;
            BIT32SET(&instX->inst32, 30, 2, bits[30]); // opc
            BIT32MASKSET(&instX->inst32, &instX->mask32, 27, 3, 0b011);
            BIT32SET(&instX->inst32, 26, 1, bits[26]); // V
            BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 2, 0b00);
            BIT32SET(&instX->inst32, 5, 19, bits[5]); // label
            BIT32SET(&instX->inst32, 0, 5, bits[0]);  // Rt
            break;

        case MULTICLASS(CBZ, W):
            parentId = MULTICLASS(CmpBranch, W);
            bits[24] = 0; // op
            BIT32SETMASK(&instX->mask32, 24, 1);
            break;
        case MULTICLASS(CBNZ, W):
            parentId = MULTICLASS(CmpBranch, W);
            bits[24] = 1; // op
            BIT32SETMASK(&instX->mask32, 24, 1);
            break;
        case MULTICLASS(CmpBranch, W):
            parentId = BaseCmpBranch;
            BIT32MASKSET(&instX->inst32, &instX->mask32, 31, 1, 0);
            break;
        case MULTICLASS(CBZ, X):
            parentId = MULTICLASS(CmpBranch, X);
            bits[24] = 0; // op
            BIT32SETMASK(&instX->mask32, 24, 1);
            break;
        case MULTICLASS(CBNZ, X):
            parentId = MULTICLASS(CmpBranch, X);
            bits[24] = 1; // op
            BIT32SETMASK(&instX->mask32, 24, 1);
            break;
        case MULTICLASS(CmpBranch, X):
            parentId = BaseCmpBranch;
            BIT32MASKSET(&instX->inst32, &instX->mask32, 31, 1, 0);
            break;
        case BaseCmpBranch:
            parentId = ARM64_INST_END;
            BIT32MASKSET(&instX->inst32, &instX->mask32, 25, 6, 0b011010);
            BIT32SET(&instX->inst32, 24, 1, bits[24]); // op
            BIT32SET(&instX->inst32, 5, 19, bits[5]);  // target
            BIT32SET(&instX->inst32, 0, 5, bits[0]);   // Rt
            break;

        case Bcc:
            parentId = BranchCond;
            break;
        case BranchCond:
            parentId = ARM64_INST_END;
            BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 8, 0b01010100);
            BIT32SET(&instX->inst32, 5, 19, bits[5]); // target
            BIT32MASKSET(&instX->inst32, &instX->mask32, 4, 1, 0);
            BIT32SET(&instX->inst32, 0, 4, bits[0]); //cond
            break;

        case MULTICLASS(TBZ, W):
            parentId = MULTICLASS(TestBranch, W);
            bits[24] = 0; // op
            BIT32SETMASK(&instX->mask32, 24, 1);
            break;
        case MULTICLASS(TBNZ, W):
            parentId = MULTICLASS(TestBranch, W);
            bits[24] = 1; // op
            BIT32SETMASK(&instX->mask32, 24, 1);
            break;
        case MULTICLASS(TestBranch, W):
            parentId = BaseTestBranch;
            BIT32MASKSET(&instX->inst32, &instX->mask32, 31, 1, 0);
            break;
        case MULTICLASS(TBZ, X):
            parentId = MULTICLASS(TestBranch, X);
            bits[24] = 0; // op
            BIT32SETMASK(&instX->mask32, 24, 1);
            break;
        case MULTICLASS(TBNZ, X):
            parentId = MULTICLASS(TestBranch, X);
            bits[24] = 1; // op
            BIT32SETMASK(&instX->mask32, 24, 1);
            break;
        case MULTICLASS(TestBranch, X):
            parentId = BaseTestBranch;
            BIT32MASKSET(&instX->inst32, &instX->mask32, 31, 1, 0);
            break;
        case BaseTestBranch:
            parentId = ARM64_INST_END;
            BIT32MASKSET(&instX->inst32, &instX->mask32, 25, 6, 0b011011);
            BIT32SET(&instX->inst32, 24, 1, bits[24]); // op
            BIT32SET(&instX->inst32, 19, 4, bits[19]); // bits_19_4
            BIT32SET(&instX->inst32, 5, 14, bits[5]);  // target
            BIT32SET(&instX->inst32, 0, 5, bits[0]);   // Rt
            break;

        case B:
            parentId = BranchImm;
            bits[31] = 0; // op
            BIT32SETMASK(&instX->mask32, 31, 1);
            break;
        case BranchImm:
            parentId = BImm;
            break;
        case BL:
            parentId = CallImm;
            bits[31] = 0; // op
            BIT32SETMASK(&instX->mask32, 31, 1);
            break;
        case CallImm:
            parentId = BImm;
            break;
        case BImm:
            BIT32SET(&instX->inst32, 31, 1, bits[31]); // op
            BIT32MASKSET(&instX->inst32, &instX->mask32, 26, 5, 0b00101);
            BIT32SET(&instX->inst32, 0, 26, bits[0]); // addr
            break;
        default:
            return;
        }
        id = parentId;
    } while (id > 0);
}
#endif

ARM64InstructionX ARM64InstArrary[1024] = {0};

ARM64InstId getInstType(uint32_t inst32) {
    for (int i = ARM64_INST_START; i < ARM64_INST_END; i++) {
        ARM64InstructionX *instX =
            (ARM64InstructionX *)((uintptr_t)ARM64InstArrary + (int)i * sizeof(ARM64InstructionX));
        uint32_t bits[4 * WORD_SIZE] = {0}; // trick :) AKA LLVM bits<>
        
        if(!instX->inst32)
            continue;
        if ((instX->mask32 & inst32) == instX->inst32) {
            return i;
        }
    }
    return ARM64_INST_END;
}

__attribute__((constructor)) void initializeARM64InstructionX() {
    ARM64InstArrary[LoadLiteral]   = (ARM64InstructionX){0 | 0b011 << 27 | 0b00 << 24, 0 | 0b111 << 27 | 0b11 << 24};
    ARM64InstArrary[BaseCmpBranch] = (ARM64InstructionX){0 | 0b011010 << 25, 0b111111 << 25};
    ARM64InstArrary[BranchCond]    = (ARM64InstructionX){0 | 0b01010100 << 24 | 0 << 4, 0 | 0b11111111 << 24 | 1 << 4};
    ARM64InstArrary[B]             = (ARM64InstructionX){0 | 0 << 31 | 0b00101 << 26, 0 | 1 << 31 | 0b11111 << 26};
    ARM64InstArrary[BL]            = (ARM64InstructionX){0 | 1 << 31 | 0b00101 << 26, 0 | 1 << 31 | 0b11111 << 26};
    return;
}
