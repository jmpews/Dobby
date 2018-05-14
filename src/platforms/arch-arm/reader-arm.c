#include "reader-arm.h"
#include <stdlib.h>

ARMReader *arm_reader_new(zz_ptr_t insn_address) {
    ARMReader *reader = (ARMReader *)malloc0(sizeof(ARMReader));

    reader->start_pc          = (zz_addr_t)insn_address + 8;
    reader->insns_buffer   = (zz_addr_t)insn_address;
    reader->insns_size              = 0;
    reader->insnCTXs_count         = 0;
    return reader;
}

void arm_reader_init(ARMReader *self, zz_ptr_t insn_address) { arm_reader_reset(self, insn_address); }

void arm_reader_reset(ARMReader *self, zz_ptr_t insn_address) {
    self->start_pc          = (zz_addr_t)insn_address + 8;
    self->insns_buffer   = (zz_addr_t)insn_address;
    self->insns_size              = 0;
    self->insnCTXs_count         = 0;
}

void arm_reader_free(ARMReader *self) {
    if (self->insnCTXs_count) {
        for (int i = 0; i < self->insnCTXs_count; i++) {
            free(self->insnCTXs[i]);
        }
    }
    free(self);
}

ARMInstruction *arm_reader_read_one_instruction(ARMReader *self) {
    ARMInstruction *insn_ctx = (ARMInstruction *)malloc0(sizeof(ARMInstruction));
    zz_addr_t next_insn_address = (zz_addr_t)self->insns_buffer + self->insns_size;
    insn_ctx->type             = ARM_INSN;
    insn_ctx->pc      = next_insn_address;
    insn_ctx->address = next_insn_address;
    insn_ctx->insn    = *(uint32_t *)next_insn_address;

    self->insnCTXs[self->insnCTXs_count++] = insn_ctx;
    self->insns_size += insn_ctx->size;
    return insn_ctx;
}

// ARM Manual
// A5 ARM Instruction Set Encoding
// A5.3 Load/store word and unsigned byte
ARMInsnType GetARMInsnType(uint32_t insn) {

    if (insn_equal(insn, "xxxx0000100xxxxxxxxxxxxxxxx0xxxx") && (get_insn_sub(insn, 28, 4) != 0xF)) {
        return ARM_INS_ADD_register_A1;
    }

    if (insn_equal(insn, "xxxx0101x0011111xxxxxxxxxxxxxxxx") && (get_insn_sub(insn, 28, 4) != 0xF)) {
        return ARM_INS_LDR_literal_A1;
    }

    if (insn_equal(insn, "xxxx001010001111xxxxxxxxxxxxxxxx") && (get_insn_sub(insn, 28, 4) != 0xF)) {
        return ARM_INS_ADR_A1;
    }
    if (insn_equal(insn, "xxxx001001001111xxxxxxxxxxxxxxxx") && (get_insn_sub(insn, 28, 4) != 0xF)) {
        return ARM_INS_ADR_A2;
    }
    if (insn_equal(insn, "xxxx1010xxxxxxxxxxxxxxxxxxxxxxxx") && (get_insn_sub(insn, 28, 4) != 0xF)) {
        return ARM_INS_B_A1;
    }
    if (insn_equal(insn, "xxxx1011xxxxxxxxxxxxxxxxxxxxxxxx") && (get_insn_sub(insn, 28, 4) != 0xF)) {
        return ARM_INS_BLBLX_immediate_A1;
    }
    if (insn_equal(insn, "1111101xxxxxxxxxxxxxxxxxxxxxxxxx")) {
        return ARM_INS_BLBLX_immediate_A2;
    }

    return ARM_UNDEF;
}