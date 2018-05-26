//
// Created by jmpews on 2018/5/14.
//

#include "ARM64AssemblyCore.h"

#define INST_FUNC_INITIALIZE(func, ...) func(inst, ##__VA_ARGS__)
#define WORD_SIZE 8

// clang-format off
// automatic generation
ARM64InstructionX ARM64InstArrary[1024] = {0};
// clang-format on

void ARM64CoreINIT(ARM64InstId id) {
    ARM64InstructionX *instX = (ARM64InstructionX *) ((uintptr_t) ARM64InstArrary +
                                                      (int) id * sizeof(ARM64InstructionX));
    int parentId = -1;
    uint32_t bits[4 * WORD_SIZE] = {0}; // trick :) AKA LLVM bits<>

    do {
        switch (id) {
            case LDRWl:
                parentId = LoadLiteral;
                BIT32MASKSET(&instX->inst32, &instX->mask32, 30, 2, 0b00); // opc
                BIT32MASKSET(&instX->inst32, &instX->mask32, 26, 1, 0);    // V
                break;
            case LDRXl:
                parentId = LoadLiteral;
                BIT32MASKSET(&instX->inst32, &instX->mask32, 30, 2, 0b01); // opc
                BIT32MASKSET(&instX->inst32, &instX->mask32, 26, 1, 0);    // V
                break;
            case LoadLiteral:
                parentId = UNKNOWN;
                BIT32SET(&instX->inst32, 30, 2, bits[30]); // opc
                BIT32MASKSET(&instX->inst32, &instX->mask32, 27, 3, 0b011);
                BIT32SET(&instX->inst32, 26, 1, bits[26]); // V
                BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 2, 0b00);
                BIT32SET(&instX->inst32, 5, 19, bits[5]); // label
                BIT32SET(&instX->inst32, 0, 5, bits[0]);  // Rt
                break;

            case MULTICLASS(CBZ, W):
                parentId = MULTICLASS(CmpBranch, W);
                BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 1, 0); // op
                break;
            case MULTICLASS(CBNZ, W):
                parentId = MULTICLASS(CmpBranch, W);
                BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 1, 1); // op
                break;
            case MULTICLASS(CmpBranch, W):
                parentId = BaseCmpBranch;
                BIT32MASKSET(&instX->inst32, &instX->mask32, 31, 1, 0);
                break;
            case MULTICLASS(CBZ, X):
                parentId = MULTICLASS(CmpBranch, X);
                BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 1, 0); // op
                break;
            case MULTICLASS(CBNZ, X):
                parentId = MULTICLASS(CmpBranch, X);
                BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 1, 1); // op
                break;
            case MULTICLASS(CmpBranch, X):
                parentId = BaseCmpBranch;
                BIT32MASKSET(&instX->inst32, &instX->mask32, 31, 1, 0);
                break;
            case BaseCmpBranch:
                parentId= UNKNOWN;
                BIT32MASKSET(&instX->inst32, &instX->mask32, 25, 6, 0b011010);
                BIT32SET(&instX->inst32, 24, 1, bits[24]); // op
                BIT32SET(&instX->inst32, 5, 19, bits[5]); // target
                BIT32SET(&instX->inst32, 0, 5, bits[0]); // Rt
                break;

            case Bcc:
                parentId= BranchCond;
                break;
            case BranchCond:
                parentId= UNKNOWN;
                BIT32MASKSET(&instX->inst32, &instX->mask32,24, 8, 0b01010100);
                BIT32SET(&instX->inst32, 5, 19, bits[5]); // target
                BIT32MASKSET(&instX->inst32, &instX->mask32,4, 1, 0);
                BIT32SET(&instX->inst32, 0, 4, bits[0]); //cond
                break;

            case MULTICLASS(TBZ, W):
                parentId= MULTICLASS(TestBranch, W);
                BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 1, 0); // op
                break;
            case MULTICLASS(TBNZ, W):
                parentId= MULTICLASS(TestBranch, W);
                BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 1, 1); // op
                break;
            case MULTICLASS(TestBranch, W):
                parentId= BaseTestBranch;
                BIT32MASKSET(&instX->inst32, &instX->mask32, 31, 1, 0);
                break;
            case MULTICLASS(TBZ, X):
                parentId= MULTICLASS(TestBranch, X);
                BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 1, 0); // op
                break;
            case MULTICLASS(TBNZ, X):
                parentId= MULTICLASS(TestBranch, X);
                BIT32MASKSET(&instX->inst32, &instX->mask32, 24, 1, 1); // op
                break;
            case  MULTICLASS(TestBranch, X):
                parentId= BaseTestBranch;
                BIT32MASKSET(&instX->inst32, &instX->mask32, 31, 1, 0);
                break;
            case BaseTestBranch:
                parentId= UNKNOWN;
                BIT32MASKSET(&instX->inst32, &instX->mask32, 25, 6, 0b011011);
                BIT32SET(&instX->inst32, 24, 1, bits[24]); // op
                BIT32SET(&instX->inst32, 19, 4, bits[19]); // bits_19_4
                BIT32SET(&instX->inst32, 5, 14, bits[5]); // target
                BIT32SET(&instX->inst32, 0, 5, bits[0]); // Rt
                break;

            case B:
                parentId= BranchImm;
                BIT32MASKSET(&instX->inst32, &instX->mask32, 31, 1, 0); // op
                break;
            case BranchImm:
                parentId= BImm;
                break;
            case BL:
                parentId= CallImm;
                BIT32MASKSET(&instX->inst32, &instX->mask32, 31, 1, 1); // op
                break;
            case CallImm:
                parentId= BImm;
                break;
            case BImm:
                BIT32SET(&instX->inst32, 31, 1, bits[31]); // op
                BIT32MASKSET(&instX->inst32, &instX->mask32, 26, 5, 0b00101);
                BIT32SET(&instX->inst32, 0, 26, bits[0]); // addr
                break;
        }
        id = parentId;
    } while (id > 0);
}

ARM64InstId getInstType(uint32_t inst32) {
    for (int i = 0; i < 1024; i++) {
        ARM64InstructionX *instX =
                (ARM64InstructionX *) ((uintptr_t) ARM64InstArrary +
                                       (int) i * sizeof(ARM64InstructionX));
        uint32_t bits[4 * WORD_SIZE] = {0}; // trick :) AKA LLVM bits<>

        if (instX->inst32 == 0) {
            return 0;
        }

        if ((instX->inst32 & inst32) == instX->inst32) {
            return i;
        }
    }
}