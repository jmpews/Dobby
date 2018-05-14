#include "reader-thumb.h"

bool insn_is_thumb2(uint32_t insn) {
    // PAGE: A6-221
    // PAGE: A6-230

    if (insn_equal(insn & 0x0000FFFF, "11101xxxxxxxxxxx") || insn_equal(insn & 0x0000FFFF, "11111xxxxxxxxxxx") ||
        insn_equal(insn & 0x0000FFFF, "11110xxxxxxxxxxx")) {
        return TRUE;
    } else {
        return FALSE;
    }
}

ARMReader *thumb_reader_new(zz_ptr_t insn_address) {
    ARMReader *reader = (ARMReader *)malloc0(sizeof(ARMReader));

    reader->start_pc                = (zz_addr_t )insn_address + 4;
    reader->insns_buffer   = (zz_addr_t)insn_address;
    reader->insns_size              = 0;
    reader->insnCTXs_count         = 0;
    return reader;
}

void thumb_reader_init(ARMReader *self, zz_ptr_t insn_address) { thumb_reader_reset(self, insn_address); }

void thumb_reader_reset(ARMReader *self, zz_ptr_t insn_address) {
    self->start_pc                = (zz_addr_t )insn_address + 4;
    self->insns_buffer   = (zz_addr_t )insn_address;
    self->insns_size              = 0;
    self->insnCTXs_count         = 0;
}

void thumb_reader_free(ARMReader *self) {
    if (self->insnCTXs_count) {
        for (int i = 0; i < self->insnCTXs_count; i++) {
            free(self->insnCTXs[i]);
        }
    }
    free(self);
}

ARMInstruction *thumb_reader_read_one_instruction(ARMReader *self) {
    ARMInstruction *insn_ctx          = (ARMInstruction *)malloc0(sizeof(ARMInstruction));
    zz_addr_t next_insn_address = (zz_addr_t)self->insns_buffer + self->insns_size;
    insn_ctx->type    = THUMB_INSN;
    insn_ctx->pc      = next_insn_address;
    insn_ctx->address = next_insn_address;
    insn_ctx->insn    = *(uint32_t *)next_insn_address;

    // PAGE: A6-221
    if (insn_is_thumb2(insn_ctx->insn)) {
        insn_ctx->type  = THUMB2_INSN;
        insn_ctx->size  = 4;
        insn_ctx->insn1 = insn_ctx->insn & 0x0000FFFF;
        insn_ctx->insn2 = (insn_ctx->insn & 0xFFFF0000) >> 16;
    } else {
        insn_ctx->type  = THUMB_INSN;
        insn_ctx->size  = 2;
        insn_ctx->insn1 = insn_ctx->insn & 0x0000FFFF;
        insn_ctx->insn2 = 0;
    }

    self->insnCTXs[self->insnCTXs_count++] = insn_ctx;
    self->insns_size += insn_ctx->size;
    return insn_ctx;
}

// ARM Manual
// A5 ARM Instruction Set Encoding
// A5.3 Load/store word and unsigned byte
THUMBInsnType GetTHUMBInsnType(uint16_t insn1, uint16_t insn2) {

    if (!insn_is_thumb2(insn1) && insn_equal(insn1, "1011x0x1xxxxxxxx")) {
        return THUMB_INS_CBNZ_CBZ;
    }

    if (!insn_is_thumb2(insn1) && insn_equal(insn1, "01000100xxxxxxxx")) {
        return THUMB_INS_ADD_register_T2;
    }

    if (!insn_is_thumb2(insn1) && insn_equal(insn1, "01001xxxxxxxxxxx")) {
        return THUMB_INS_LDR_literal_T1;
    }

    if (insn_is_thumb2(insn1) && insn_equal(insn1, "11111000x1011111") && insn_equal(insn2, "xxxxxxxxxxxxxxxx")) {
        return THUMB_INS_LDR_literal_T2;
    }

    if (!insn_is_thumb2(insn1) && insn_equal(insn1, "10100xxxxxxxxxxx")) {
        return THUMB_INS_ADR_T1;
    }

    if (insn_is_thumb2(insn1) && insn_equal(insn1, "11110x1010101111") && insn_equal(insn2, "0xxxxxxxxxxxxxxx")) {
        return THUMB_INS_ADR_T2;
    }

    if (insn_is_thumb2(insn1) && insn_equal(insn1, "11110x1000001111") && insn_equal(insn2, "0xxxxxxxxxxxxxxx")) {
        return THUMB_INS_ADR_T3;
    }

    if (!insn_is_thumb2(insn1) && insn_equal(insn1, "1101xxxxxxxxxxxx")) {
        int cond = get_insn_sub(insn1, 8, 4);
        if(cond != 0b1110 && cond != 0b1111) {
            return THUMB_INS_B_T1;
        }
    }

    if (!insn_is_thumb2(insn1) && insn_equal(insn1, "11100xxxxxxxxxxx")) {
        return THUMB_INS_B_T2;
    }

    if (insn_is_thumb2(insn1) && insn_equal(insn1, "11110xxxxxxxxxxx") && insn_equal(insn2, "10x0xxxxxxxxxxxx")) {
        return THUMB_INS_B_T3;
    }

    if (insn_is_thumb2(insn1) && insn_equal(insn1, "11110xxxxxxxxxxx") && insn_equal(insn2, "10x1xxxxxxxxxxxx")) {
        return THUMB_INS_B_T4;
    }

    if (insn_is_thumb2(insn1) && insn_equal(insn1, "11110xxxxxxxxxxx") && insn_equal(insn2, "11x1xxxxxxxxxxxx")) {
        return THUMB_INS_BLBLX_immediate_T1;
    }

    if (insn_is_thumb2(insn1) && insn_equal(insn1, "11110xxxxxxxxxxx") && insn_equal(insn2, "11x0xxxxxxxxxxxx")) {
        return THUMB_INS_BLBLX_immediate_T2;
    }

    return THUMB_UNDEF;
}