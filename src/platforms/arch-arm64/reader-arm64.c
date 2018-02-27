#include "reader-arm64.h"
ZzARM64Reader *zz_arm64_reader_new(zz_ptr_t insn_address) {
    ZzARM64Reader *reader = (ZzARM64Reader *)zz_malloc_with_zero(sizeof(ZzARM64Reader));

    reader->r_start_address   = (zz_addr_t)insn_address;
    reader->r_current_address = (zz_addr_t)insn_address;
    reader->start_pc          = (zz_addr_t)insn_address;
    reader->current_pc        = (zz_addr_t)insn_address;
    reader->size              = 0;
    reader->insn_size         = 0;
    return reader;
}

void zz_arm64_reader_init(ZzARM64Reader *self, zz_ptr_t insn_address) { zz_arm64_reader_reset(self, insn_address); }

void zz_arm64_reader_reset(ZzARM64Reader *self, zz_ptr_t insn_address) {
    self->r_start_address   = (zz_addr_t)insn_address;
    self->r_current_address = (zz_addr_t)insn_address;
    self->start_pc          = (zz_addr_t)insn_address;
    self->current_pc        = (zz_addr_t)insn_address;
    self->size              = 0;
    self->insn_size         = 0;
}

void zz_arm64_reader_free(ZzARM64Reader *self) {
    if (self->insn_size) {
        for (int i = 0; i < self->insn_size; i++) {
            free(self->insns[i]);
        }
    }
    free(self);
}

ZzARM64Instruction *zz_arm64_reader_read_one_instruction(ZzARM64Reader *self) {
    ZzARM64Instruction *insn_ctx = (ZzARM64Instruction *)zz_malloc_with_zero(sizeof(ZzARM64Instruction));
    insn_ctx->address            = (zz_addr_t)self->r_current_address;
    insn_ctx->pc                 = (zz_addr_t)self->current_pc;
    insn_ctx->insn               = *(uint32_t *)self->r_current_address;
    insn_ctx->size               = 4;

    self->current_pc += insn_ctx->size;
    self->r_current_address += insn_ctx->size;
    self->insns[self->insn_size++] = insn_ctx;
    self->size += insn_ctx->size;
    return insn_ctx;
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