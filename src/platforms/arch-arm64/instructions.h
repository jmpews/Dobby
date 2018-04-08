#ifndef arch_arm64_instructions_h
#define arch_arm64_instructions_h

#include "zkit.h"

typedef struct _ARM64Instruction {
    zz_addr_t pc;
    zz_addr_t address;
    uint8_t size;
    uint32_t insn;
    char *data;
} ARM64Instruction;

// get hex insn sub
uint32_t get_insn_sub(uint32_t insn, int start, int length);

// equal insn with mask string
bool insn_equal(uint32_t insn, char *opstr);
#endif
