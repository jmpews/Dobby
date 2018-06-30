#ifndef platforms_arch_arm64_instruction_h
#define platforms_arch_arm64_instruction_h

#include "hookzz.h"

typedef struct _ARM64InstructionCTX {
    zz_addr_t pc;
    zz_addr_t address;
    uint8_t size;
    uint32_t bytes;
} ARM64InstructionCTX;

// get hex insn sub
uint32_t get_insn_sub(uint32_t insn, int start, int length);

#endif
