#ifndef platforms_arch_arm64_instructions_h
#define platforms_arch_arm64_instructions_h

#include "kitzz.h"

typedef struct _ZzInstruction {
    zz_addr_t pc;
    zz_addr_t address;
    uint8_t size;
    uint32_t insn;
} ZzInstruction;

typedef struct _ZzRelocateInstruction {
    const ZzInstruction *insn_ctx;
    zz_addr_t relocated_offset;
    zz_size_t relocated_length;
} ZzRelocateInstruction;

// get hex insn sub
uint32_t get_insn_sub(uint32_t insn, int start, int length);

// equal insn with mask string
bool insn_equal(uint32_t insn, char *opstr);
#endif
