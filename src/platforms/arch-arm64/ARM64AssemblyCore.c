//
// Created by jmpews on 2018/5/14.
//

#include "ARM64AssemblyCore.h"

#define INST_FUNC_INITIALIZE(func, ...) func(inst, ##__VA_ARGS__)
#define WORD_SIZE 8

// clang-format off
// automatic generation
ARM64InstructionX ARM64InstArrary[1024] = {0};
OP OPArray[1024] = {0};
// clang-format on

void intializeAssemblyCore() {
    uintptr_t opIndex = 0;
    ARM64InstId id;

    id                              = LoadLiteral;
    ARM64InstArrary[id].id          = id;
    ARM64InstArrary[id].isClass     = 1;
    ARM64InstArrary[id].parentIndex = -1;
    ARM64CoreINIT(id);

    id                  = LDRWl;
    ARM64InstArrary[id] = (ARM64InstructionX){id, 0, LoadLiteral, 0, 0};
    ARM64CoreINIT(id);

    id                     = LDRXl;
    ARM64InstArrary[LDRXl] = (ARM64InstructionX){id, 0, LoadLiteral, 0, 0};
    ARM64CoreINIT(id);

    //  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    id                              = BaseCmpBranch;
    ARM64InstArrary[id].id          = id;
    ARM64InstArrary[id].isClass     = 1;
    ARM64InstArrary[id].parentIndex = -1;
    ARM64CoreINIT(id);

    id                              = MULTICLASS(CmpBranch, W);
    ARM64InstArrary[id].id          = id;
    ARM64InstArrary[id].isClass     = 1;
    ARM64InstArrary[id].parentIndex = BaseCmpBranch;
    ARM64CoreINIT(id);

    id                     = MULTICLASS(CBZ, W);
    ARM64InstArrary[LDRXl] = (ARM64InstructionX){id, 0, MULTICLASS(CmpBranch, W), 0, 0};
    ARM64CoreINIT(id);

    id                     = MULTICLASS(CBNZ, W);
    ARM64InstArrary[LDRXl] = (ARM64InstructionX){id, 0, MULTICLASS(CmpBranch, W), 0, 0};
    ARM64CoreINIT(id);

    id                              = MULTICLASS(CmpBranch, X);
    ARM64InstArrary[id].id          = id;
    ARM64InstArrary[id].isClass     = 1;
    ARM64InstArrary[id].parentIndex = BaseCmpBranch;
    ARM64CoreINIT(id);

    id                     = MULTICLASS(CBZ, X);
    ARM64InstArrary[LDRXl] = (ARM64InstructionX){id, 0, MULTICLASS(CmpBranch, X), 0, 0};
    ARM64CoreINIT(id);

    id                     = MULTICLASS(CBNZ, X);
    ARM64InstArrary[LDRXl] = (ARM64InstructionX){id, 0, MULTICLASS(CmpBranch, X), 0, 0};
    ARM64CoreINIT(id);

    //  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
}

void ARM64CoreINIT(ARM64InstId id) {
    ARM64InstructionX *instX = (ARM64InstructionX *)((uintptr_t)ARM64InstArrary + (int)id * sizeof(ARM64InstructionX));
    ARM64InstructionX *tmpInstX = instX;

    uint32_t bits[4 * WORD_SIZE] = {0}; // trick :) AKA LLVM bits<>

    do {
        switch (id) {
        case LDRWl: {
            BIT32MASKSET(&instX->inst32, &instX->mask32, 30, 2, 0b00); // opc
            BIT32MASKSET(&instX->inst32, &instX->mask32, 26, 1, 0);    // V
        }; break;
        case LDRXl: {
            BIT32MASKSET(&instX->inst32, &instX->mask32, 30, 2, 0b01); // opc
            BIT32MASKSET(&instX->inst32, &instX->mask32, 26, 1, 0);    // V
        }; break;
        case LoadLiteral: {
            BIT32SET(&instX->inst32, 30, 2, bits[30]); // opc
            BIT32MASKSET(&instX->inst32, &instX->mask32, 27, 3, 0b011);
            BIT32SET(&instX->inst32, 26, 1, bits[26]); // V
            BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 2, 0b00);
            BIT32SET(&instX->inst32, 5, 19, bits[5]); // label
            BIT32SET(&instX->inst32, 0, 5, bits[0]);  // Rt
        }; break;
        case MULTICLASS(CBZ, W):
            BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 1, 0); // op
            break;
        case MULTICLASS(CBNZ, W):
            BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 1, 1); // op
            break;
        case MULTICLASS(CmpBranch, W):
            BIT32MASKSET(&instX->inst32, &instX->mask32, 31, 1, 1);
            break;
        case MULTICLASS(CBZ, X):
            BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 1, 0); // op
            break;
        case MULTICLASS(CBNZ, X):
            BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 1, 1); // op
            break;
        case MULTICLASS(CmpBranch, X):
            BIT32MASKSET(&instX->inst32, &instX->mask32, 31, 1, 0);
            break;
        case BaseCmpBranch:
            BIT32MASKSET(&instX->inst32, &instX->mask32, 25, 6, 0b011010);
            BIT32SET(&instX->inst32, 24, 1, bits[24]);
            BIT32SET(&instX->inst32, 5, 19, bits[5]);
            BIT32SET(&instX->inst32, 0, 5, bits[0]);
            break;
        }
        id       = tmpInstX->parentIndex;
        tmpInstX = (ARM64InstructionX *)((uintptr_t)ARM64InstArrary + (int)id * sizeof(ARM64InstructionX));
    } while (tmpInstX->parentIndex && instX->inst32);
}

ARM64InstId getInstType(uint32_t inst32) {
    for (int i = 0; i < 1024; i++) {
        ARM64InstructionX *instX =
            (ARM64InstructionX *)((uintptr_t)ARM64InstArrary + (int)i * sizeof(ARM64InstructionX));
        uint32_t bits[4 * WORD_SIZE] = {0}; // trick :) AKA LLVM bits<>

        if (instX->inst32 == 0) {
            return 0;
        }

        if ((instX->inst32 & inst32) == instX->inst32) {
            return i;
        }
    }
}