#ifndef platforms_arch_arm_instructions_h
#define platforms_arch_arm_instructions_h

#include "hookzz.h"
#include "zkit.h"

typedef enum _INSN_TYPE { ARM_INSN, THUMB_INSN, THUMB2_INSN, UNKOWN_INSN } InsnType;

typedef struct _ZzARMInstruction {
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
    char *data;
} ZzARMInstruction;

uint32_t get_insn_sub(uint32_t insn, int start, int length);
bool insn_equal(uint32_t insn, char *opstr);

#endif