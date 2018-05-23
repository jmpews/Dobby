//
// Created by jmpews on 2018/5/14.
//

#include "ARM64AssemblyCore.h"

#define INST_FUNC_INITIALIZE(func, ...) func(inst, ##__VA_ARGS__)
#define WORD_SIZE 8

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

ARM64InstId Decode(uint32_t inst32) {
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