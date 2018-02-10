#ifndef platforms_arch_arm64_instructions_h
#define platforms_arch_arm64_instructions_h

#include "kitzz.h"

typedef struct _ZzARM64Instruction {
    zz_addr_t pc;
    zz_addr_t address;
    uint8_t size;
    uint32_t insn;
    char *data;
} ZzARM64Instruction;

// get hex insn sub
uint32_t get_insn_sub(uint32_t insn, int start, int length);

// equal insn with mask string
bool insn_equal(uint32_t insn, char *opstr);
#endif
