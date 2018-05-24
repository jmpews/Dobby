//
// Created by jmpews on 2018/5/14.
//

#include "ARM64AssemblyCore.h"

#define INST_FUNC_INITIALIZE(func, ...) func(inst, ##__VA_ARGS__)
#define WORD_SIZE 8

// clang-format off
// automatic generation
ARM64InstructionX ARM64InstArrary[1024];
OP OPArray[1024];
// clang-format on

void intializeAssemblyCore() {
    uintptr_t opIndex = 0;
    ARM64InstId id;

    id                              = LoadLiteral;
    ARM64InstArrary[id].id          = id;
    ARM64InstArrary[id].isClass     = 1;
    ARM64InstArrary[id].parentIndex = -1;
    ARM64InstArrary[id].inst32      = 0;
    ARM64InstArrary[id].mask32      = 0;
    ARM64InstArrary[id].opCount     = 4;
    ARM64InstArrary[id].opIndex     = 0;
    Encode(LoadLiteral, 0, 0, 0, 0);

    id                  = LDRWl;
    opIndex             = ARM64InstArrary[id - 1].opIndex + ARM64InstArrary[id - 1].opCount;
    ARM64InstArrary[id] = (ARM64InstructionX){id, 0, LoadLiteral, 0, 2, opIndex};
    Encode(id, 0, 0);

    id                     = LDRXl;
    opIndex                = ARM64InstArrary[id - 1].opIndex + ARM64InstArrary[id - 1].opCount;
    ARM64InstArrary[LDRXl] = (ARM64InstructionX){id, 0, LoadLiteral, 0, 2, opIndex};
    Encode(id, 0, 0);

    //  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    id                              = BaseCmpBranch;
    opIndex                         = ARM64InstArrary[id - 1].opIndex + ARM64InstArrary[id - 1].opCount;
    ARM64InstArrary[id].id          = id;
    ARM64InstArrary[id].isClass     = 1;
    ARM64InstArrary[id].parentIndex = -1;
    ARM64InstArrary[id].inst32      = 0;
    ARM64InstArrary[id].mask32      = 0;
    ARM64InstArrary[id].opCount     = 3;
    ARM64InstArrary[id].opIndex     = opIndex;
    Encode(LoadLiteral, 0, 0, 0);

    id                              = MULTICLASS(CmpBranch, W);
    opIndex                         = ARM64InstArrary[id - 1].opIndex + ARM64InstArrary[id - 1].opCount;
    ARM64InstArrary[id].id          = id;
    ARM64InstArrary[id].isClass     = 1;
    ARM64InstArrary[id].parentIndex = BaseCmpBranch;
    ARM64InstArrary[id].inst32      = 0;
    ARM64InstArrary[id].mask32      = 0;
    ARM64InstArrary[id].opCount     = 3;
    ARM64InstArrary[id].opIndex     = opIndex;
    Encode(LoadLiteral, 0, 0, 0);

    id                     = MULTICLASS(CBZ, W);
    opIndex                = ARM64InstArrary[id - 1].opIndex + ARM64InstArrary[id - 1].opCount;
    ARM64InstArrary[LDRXl] = (ARM64InstructionX){id, 0, MULTICLASS(CmpBranch, W), 0, 2, opIndex};
    Encode(id, 0, 0);

    id                     = MULTICLASS(CBNZ, W);
    opIndex                = ARM64InstArrary[id - 1].opIndex + ARM64InstArrary[id - 1].opCount;
    ARM64InstArrary[LDRXl] = (ARM64InstructionX){id, 0, MULTICLASS(CmpBranch, W), 0, 2, opIndex};
    Encode(id, 0, 0);

    id                              = MULTICLASS(CmpBranch, X);
    opIndex                         = ARM64InstArrary[id - 1].opIndex + ARM64InstArrary[id - 1].opCount;
    ARM64InstArrary[id].id          = id;
    ARM64InstArrary[id].isClass     = 1;
    ARM64InstArrary[id].parentIndex = BaseCmpBranch;
    ARM64InstArrary[id].inst32      = 0;
    ARM64InstArrary[id].mask32      = 0;
    ARM64InstArrary[id].opCount     = 3;
    ARM64InstArrary[id].opIndex     = opIndex;
    Encode(LoadLiteral, 0, 0, 0);

    id                     = MULTICLASS(CBZ, X);
    opIndex                = ARM64InstArrary[id - 1].opIndex + ARM64InstArrary[id - 1].opCount;
    ARM64InstArrary[LDRXl] = (ARM64InstructionX){id, 0, MULTICLASS(CmpBranch, X), 0, 2, opIndex};
    Encode(id, 0, 0);

    id                     = MULTICLASS(CBNZ, X);
    opIndex                = ARM64InstArrary[id - 1].opIndex + ARM64InstArrary[id - 1].opCount;
    ARM64InstArrary[LDRXl] = (ARM64InstructionX){id, 0, MULTICLASS(CmpBranch, X), 0, 2, opIndex};
    Encode(id, 0, 0);

    //  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
}

void Encode(ARM64InstId id, ...) {
    ARM64InstructionX *instX = (ARM64InstructionX *)((uintptr_t)ARM64InstArrary + (int)id * sizeof(ARM64InstructionX));
    int opCount              = instX->opCount;
    uintptr_t opIndex        = instX->opIndex;
    OP *ops                  = (OP *)((uintptr_t)OPArray + (int)instX->opIndex * sizeof(OP));
    uint32_t inst32;
    uint32_t bits[4 * WORD_SIZE] = {0}; // trick :) AKA LLVM bits<>

    // va_list or uint32 ops[] + ops_len, which solution is better?
    if (instX->inst32) {
        va_list ap;
        va_start(ap, id);
        for (int i = 0; i < opCount; i++) {
            OP *opx             = ops + i;
            uint32_t op32       = va_arg(ap, uint32_t);
            bits[opx->op_start] = op32;
        }
        va_end(ap);
    }
    do {
        switch (id) {
        case LDRWl:
            if (!instX->inst32) {
                bits[30] = 0; // opc
                bits[26] = 0; // V
            }
        case LDRXl:
            if (!instX->inst32) {
                bits[30] = 0; // opc
                bits[26] = 0; // V
            }
        case LoadLiteral:
            if (!instX->inst32) {
                BIT32_CONTROL_SET(inst32, 30, 2, bits[30]); // opc
                BIT32_CONTROL_SET(inst32, 27, 3, 0b011);
                BIT32_CONTROL_SET(inst32, 26, 1, bits[26]); // V
                BIT32_CONTROL_SET(inst32, 24, 2, 0b00);
                BIT32_CONTROL_SET(inst32, 5, 19, bits[5]); // label
                BIT32_CONTROL_SET(inst32, 0, 5, bits[0]);  // Rt
            }
        }
        id    = instX->parentIndex;
        instX = (ARM64InstructionX *)((uintptr_t)ARM64InstArrary + (int)id * sizeof(ARM64InstructionX));
    } while (instX->parentIndex && instX->inst32);
}

ARM64InstId getInstType(uint32_t inst32) {
    for (int i = 0; i < 1024; i++) {
        ARM64InstructionX *instX =
            (ARM64InstructionX *)((uintptr_t)ARM64InstArrary + (int)i * sizeof(ARM64InstructionX));
        int opCount                  = instX->opCount;
        uintptr_t opIndex            = instX->opIndex;
        OP *ops                      = (OP *)((uintptr_t)OPArray + (int)instX->opIndex * sizeof(OP));
        uint32_t bits[4 * WORD_SIZE] = {0}; // trick :) AKA LLVM bits<>

        if (instX->inst32 == 0) {
            return 0;
        }

        if ((instX->inst32 & inst32) == instX->inst32) {
            return i;
        }
    }
}