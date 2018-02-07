#ifndef platforms_arch_arm64_reader_h
#define platforms_arch_arm64_reader_h

#include "kitzz.h"

#include "instructions.h"

typedef enum _ARM64InsnType {
    ARM64_INS_LDR_literal,
    ARM64_INS_ADR,
    ARM64_INS_ADRP,
    ARM64_INS_B,
    ARM64_INS_BL,
    ARM64_INS_B_cond,
    ARM64_UNDEF
} ARM64InsnType;

ARM64InsnType GetARM64InsnType(uint32_t insn);

zz_ptr_t zz_arm64_reader_read_one_instruction(zz_ptr_t address, ZzInstruction *insn_ctx);

#endif