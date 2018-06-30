#ifndef arch_x86_instructions_h
#define arch_x86_instructions_h

#include "zkit.h"

typedef struct _X86Instruction {
    zz_addr_t ip;
    zz_addr_t address;
    uint8_t size;
    char insn[16];
    char *data;
} X86Instruction;
#endif
