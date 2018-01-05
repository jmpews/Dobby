/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#ifndef platforms_arch_arm_instructions_h
#define platforms_arch_arm_instructions_h

#include "hookzz.h"
#include "kitzz.h"

typedef enum _INSN_TYPE { ARM_INSN, THUMB_INSN, THUMB2_INSN } InsnType;

typedef struct _Instruction {
    InsnType type;
    zz_addr_t pc;
    zz_addr_t address;
    uint8_t size;
    union {
        uint32_t trick_insn;
        struct {
            uint16_t trick_insn1;
            uint16_t trick_insn2;
        };
    };

    uint32_t insn;
    uint16_t insn1;
    uint16_t insn2;
} ZzInstruction;

typedef struct _ZzRelocateInstruction {
    const ZzInstruction *insn_ctx;
    zz_addr_t relocated_offset;
    zz_size_t relocated_length;
} ZzRelocateInstruction;

uint32_t get_insn_sub(uint32_t insn, int start, int length);
bool insn_equal(uint32_t insn, char *opstr);

#endif