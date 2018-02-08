#include "reader-arm64.h"

zz_ptr_t zz_arm64_reader_read_one_instruction(zz_ptr_t address, ZzInstruction *insn_ctx) {
    insn_ctx->address = (zz_addr_t)address;
    insn_ctx->size    = 4;
    insn_ctx->pc      = (zz_addr_t)address;
    insn_ctx->insn    = *(uint32_t *)address;
    return (zz_ptr_t)insn_ctx->pc;
}

ARM64InsnType GetARM64InsnType(uint32_t insn) {
    // PAGE: C6-673
    if (insn_equal(insn, "01011000xxxxxxxxxxxxxxxxxxxxxxxx")) {
        return ARM64_INS_LDR_literal;
    }

    // PAGE: C6-535
    if (insn_equal(insn, "0xx10000xxxxxxxxxxxxxxxxxxxxxxxx")) {
        return ARM64_INS_ADR;
    }

    // PAGE: C6-536
    if (insn_equal(insn, "1xx10000xxxxxxxxxxxxxxxxxxxxxxxx")) {
        return ARM64_INS_ADRP;
    }

    // PAGE: C6-550
    if (insn_equal(insn, "000101xxxxxxxxxxxxxxxxxxxxxxxxxx")) {
        return ARM64_INS_B;
    }

    // PAGE: C6-560
    if (insn_equal(insn, "100101xxxxxxxxxxxxxxxxxxxxxxxxxx")) {
        return ARM64_INS_BL;
    }

    // PAGE: C6-549
    if (insn_equal(insn, "01010100xxxxxxxxxxxxxxxxxxx0xxxx")) {
        return ARM64_INS_B_cond;
    }

    return ARM64_UNDEF;
}