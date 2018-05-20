#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "relocator-thumb.h"

#define MAX_RELOCATOR_INSTRUCIONS_SIZE 64

void thumb_relocator_init(ThumbRelocator *relocator, ARMReader *input, ThumbAssemblerWriter *output) {
    memset(relocator, 0, sizeof(ThumbRelocator));
    relocator->needRelocateInputCount = 0;
    relocator->doneRelocateInputCount = 0;
    relocator->input                  = input;
    relocator->output                 = output;
    relocator->try_relocated_length   = 0;
}

void thumb_relocator_free(ThumbRelocator *relocator) {
    thumb_reader_free(relocator->input);
    thumb_writer_free(relocator->output);
    free(relocator);
}

void thumb_relocator_reset(ThumbRelocator *self, ARMReader *input, ThumbAssemblerWriter *output) {
    self->needRelocateInputCount = 0;
    self->doneRelocateInputCount = 0;
    self->input                  = input;
    self->output                 = output;
    self->literal_insnCTXs_count = 0;
    self->try_relocated_length   = 0;
}

void thumb_relocator_read_one(ThumbRelocator *self, ARMInstruction *instruction) {
    ARMInstruction *insn_ctx;

    thumb_reader_read_one_instruction(self->input);

    // switch (1) {}

    self->needRelocateInputCount++;

    if (instruction != NULL)
        *instruction = *insn_ctx;
}

void thumb_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes) {
    int tmp_size = 0;
    bool is_thumb;
    zz_ptr_t target_addr;
    bool early_end = FALSE;
    is_thumb       = INSTRUCTION_IS_THUMB((zz_addr_t)address);

    ARMInstruction *insn_ctx;
    ARMReader *reader = thumb_reader_new(address);

    do {
        insn_ctx = thumb_reader_read_one_instruction(reader);
        switch (GetTHUMBInsnType(insn_ctx->insn1, insn_ctx->insn2)) {
        case THUMB_INS_B_T2:
            early_end = TRUE;
            break;
        case THUMB_INS_B_T4:
            early_end = TRUE;
            break;
        default:;
        }
        tmp_size += insn_ctx->size;
        target_addr = target_addr + insn_ctx->size;
    } while (tmp_size < min_bytes);

    if (early_end) {
        *max_bytes = tmp_size;
    }

    thumb_reader_free(reader);
    return;
}

#if 0
zz_addr_t thumb_relocator_get_insn_relocated_offset(ThumbRelocator *self, zz_addr_t address) {
    const ARMInstruction *insn_ctx;
    const ZzRelocateInstruction *re_insn_ctx;
    int i;

    for (i = 0; i < self->needRelocateInputCount; i++) {
        re_insn_ctx = &self->output_insnCTXs[i];
        insn_ctx    = re_insn_ctx->insn_ctx;
        if (insn_ctx->address == address && re_insn_ctx->relocated_offset) {
            return re_insn_ctx->relocated_offset;
        }
    }
    return 0;
}

#endif

static ARMRelocatorInstruction *thumb_relocator_get_relocator_insn_with_address(ThumbRelocator *self,
                                                                                zz_addr_t insn_address) {
    for (int i = 0; i < self->relocated_insnCTXs_count; ++i) {
        if ((self->relocator_insnCTXs[i].origin_insn->pc - 4) == insn_address) {
            return &self->relocator_insnCTXs[i];
        }
    }
    return NULL;
}
void thumb_relocator_relocate_writer(ThumbRelocator *relocator, zz_addr_t final_relocate_address) {
    ARMRelocatorInstruction *relocated_insn;
    if (relocator->literal_insnCTXs_count) {
        zz_addr_t *literal_target_address_ptr;
        for (int i = 0; i < relocator->literal_insnCTXs_count; i++) {
            literal_target_address_ptr = (zz_addr_t *)relocator->literal_insnCTXs[i]->address;
            // literal instruction in the range of instructions-need-fix
            if (*literal_target_address_ptr > (relocator->input->start_pc - 4) &&
                *literal_target_address_ptr < (relocator->input->start_pc - 4 + relocator->input->insns_size)) {
                relocated_insn =
                    thumb_relocator_get_relocator_insn_with_address(relocator, *literal_target_address_ptr);
                assert(relocated_insn);
                *literal_target_address_ptr =
                    (*relocated_insn->relocated_insnCTXs)->pc - relocator->output->start_pc + final_relocate_address;
            }
        }
    }
}

void thumb_relocator_write_all(ThumbRelocator *self) {
    int count                         = 0;
    int doneRelocateInputCount        = self->doneRelocateInputCount;
    ThumbAssemblerWriter thumb_writer = *self->output;
    while (thumb_relocator_write_one(self))
        count++;
}

void thumb_relocator_register_literal_insn(ThumbRelocator *self, ARMInstruction *insn_ctx) {
    self->literal_insnCTXs[self->literal_insnCTXs_count++] = insn_ctx;
    // convert the temportary absolute address with offset.
    //    zz_addr_t *temp_address = (zz_addr_t *)insn_ctx->address;
    //    *temp_address = insn_ctx->pc - self->output->start_pc;
}

// A8-357
// 0: cbz #0
// 2: b #6
// 4: ldr pc, #0
// 8: .long ?
// c: next insn
static bool thumb_relocator_rewrite_CBNZ_CBZ(ThumbRelocator *self, const ARMInstruction *insn_ctx) {

    uint32_t insn1 = insn_ctx->insn1;
    uint16_t op, i, imm5, Rn_ndx;
    uint32_t imm32, nonzero;

    op     = get_insn_sub(insn1, 11, 1);
    i      = get_insn_sub(insn1, 9, 1);
    imm5   = get_insn_sub(insn1, 3, 5);
    Rn_ndx = get_insn_sub(insn1, 0, 3);

    imm32   = imm5 << 1 | i << (5 + 1);
    nonzero = (op == 1);

    zz_addr_t target_address = insn_ctx->pc + imm32;
    zz_addr_t current_pc     = self->output->start_pc + self->output->insns_size;

    /* for align , simple solution, maybe the correct solution is get `ldr_reg_address` length and adjust the immediate
     * of `b_imm`. */
    if (current_pc % 4) {
        thumb_writer_put_nop(self->output);
    }
    thumb_writer_put_instruction(self->output, (insn1 & 0b1111110100000111) | 0);
    thumb_writer_put_b_imm(self->output, 0x6);
    thumb_writer_put_ldr_reg_address(self->output, ARM_REG_PC, target_address + 1);
    // register literal instruction
    thumb_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    return TRUE;
}

// PAGE: A8-310
static bool thumb_relocator_rewrite_ADD_register_T2(ThumbRelocator *self, const ARMInstruction *insn_ctx) {
    uint32_t insn1 = insn_ctx->insn1;

    uint16_t Rm_ndx, Rdn_ndx, DN, Rd_ndx;
    Rm_ndx  = get_insn_sub(insn1, 3, 4);
    Rdn_ndx = get_insn_sub(insn1, 0, 3);
    DN      = get_insn_sub(insn1, 7, 1);
    Rd_ndx  = (DN << 3) | Rdn_ndx;

    if (Rm_ndx != ARM_REG_PC) {
        return FALSE;
    }

    thumb_writer_put_push_reg(self->output, ARM_REG_R7);
    thumb_writer_put_ldr_b_reg_address(self->output, ARM_REG_R7, insn_ctx->pc);
    thumb_writer_put_instruction(self->output, (insn1 & 0b1111111110000111) | ARM_REG_R7 << 3);
    thumb_writer_put_pop_reg(self->output, ARM_REG_R7);

    return TRUE;
}

// PAGE: A8-410
bool thumb_relocator_rewrite_LDR_literal_T1(ThumbRelocator *self, const ARMInstruction *insn_ctx) {
    uint32_t insn1 = insn_ctx->insn1;
    uint32_t imm8  = get_insn_sub(insn1, 0, 8);
    uint32_t imm32 = imm8 << 2;
    // TODO: must be align_4 ?
    zz_addr_t target_address = ALIGN_FLOOR(insn_ctx->pc, 4) + imm32;
    int Rt_ndx               = get_insn_sub(insn1, 8, 3);

    thumb_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);
    thumb_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    thumb_writer_put_ldr_reg_reg_offset(self->output, Rt_ndx, Rt_ndx, 0);

    return TRUE;
}

// PAGE: A8-410
bool thumb_relocator_rewrite_LDR_literal_T2(ThumbRelocator *self, const ARMInstruction *insn_ctx) {
    uint32_t insn1 = insn_ctx->insn1;
    uint32_t insn2 = insn_ctx->insn2;

    uint32_t imm12 = get_insn_sub(insn2, 0, 12);
    uint32_t imm32 = imm12;

    bool add = get_insn_sub(insn_ctx->insn1, 7, 1) == 1;
    zz_addr_t target_address;
    if (add)
        target_address = ALIGN_FLOOR(insn_ctx->pc, 4) + imm32;
    else
        target_address = ALIGN_FLOOR(insn_ctx->pc, 4) - imm32;
    int Rt_ndx = get_insn_sub(insn_ctx->insn2, 12, 4);

    thumb_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);
    thumb_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    thumb_writer_put_ldr_reg_reg_offset(self->output, Rt_ndx, Rt_ndx, 0);

    return TRUE;
}

// PAGE: A8-322
bool thumb_relocator_rewrite_ADR_T1(ThumbRelocator *self, const ARMInstruction *insn_ctx) {
    uint32_t insn1 = insn_ctx->insn1;

    uint32_t imm8            = get_insn_sub(insn1, 0, 8);
    uint32_t imm32           = imm8 << 2;
    zz_addr_t target_address = insn_ctx->pc + imm32;
    int Rt_ndx               = get_insn_sub(insn1, 8, 3);

    thumb_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);
    return TRUE;
}

// PAGE: A8-322
bool thumb_relocator_rewrite_ADR_T2(ThumbRelocator *self, const ARMInstruction *insn_ctx) {
    uint32_t insn1 = insn_ctx->insn1;
    uint32_t insn2 = insn_ctx->insn2;

    uint32_t imm32 =
        get_insn_sub(insn2, 0, 8) | (get_insn_sub(insn2, 12, 3) << 8) | ((get_insn_sub(insn1, 10, 1) << (3 + 8)));

    zz_addr_t target_address;
    target_address = insn_ctx->pc - imm32;
    int Rt_ndx     = get_insn_sub(insn_ctx->insn2, 8, 4);
    thumb_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);
    return TRUE;
}

// PAGE: A8-322
bool thumb_relocator_rewrite_ADR_T3(ThumbRelocator *self, const ARMInstruction *insn_ctx) {
    uint32_t insn1 = insn_ctx->insn1;
    uint32_t insn2 = insn_ctx->insn2;

    uint32_t imm32 =
        get_insn_sub(insn2, 0, 8) | (get_insn_sub(insn2, 12, 3) << 8) | ((get_insn_sub(insn1, 10, 1) << (3 + 8)));

    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm32;
    int Rt_ndx     = get_insn_sub(insn_ctx->insn2, 8, 4);

    thumb_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);
    return TRUE;
}

// 0x000 : b.cond 0x0;
// 0x002 : b 0x6
// 0x004 : ldr pc, [pc, #0]
// 0x008 : .long 0x0
// 0x00c : remain code

// PAGE: A8-334
bool thumb_relocator_rewrite_B_T1(ThumbRelocator *self, const ARMInstruction *insn_ctx) {
    uint32_t insn1 = insn_ctx->insn1;
    // uint32_t insn2 = insn_ctx->insn2;

    uint32_t imm8            = get_insn_sub(insn1, 0, 8);
    uint32_t imm32           = imm8 << 1;
    zz_addr_t target_address = insn_ctx->pc + imm32;

    zz_addr_t current_pc = self->output->start_pc + self->output->insns_size;

    /* for align , simple solution, maybe the correct solution is get `ldr_reg_address` length and adjust the immediate
     * of `b_imm`. */
    if (current_pc % 4) {
        thumb_writer_put_nop(self->output);
    }
    thumb_writer_put_instruction(self->output, (insn1 & 0xFF00) | 0);
    thumb_writer_put_b_imm(self->output, 0x6);
    thumb_writer_put_ldr_reg_address(self->output, ARM_REG_PC, target_address + 1);
    thumb_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    return TRUE;
}

// PAGE: A8-334
bool thumb_relocator_rewrite_B_T2(ThumbRelocator *self, const ARMInstruction *insn_ctx) {
    uint32_t insn1 = insn_ctx->insn1;

    uint32_t imm11           = get_insn_sub(insn1, 0, 11);
    uint32_t imm32           = imm11 << 1;
    zz_addr_t target_address = insn_ctx->pc + imm32;

    thumb_writer_put_ldr_reg_address(self->output, ARM_REG_PC, target_address + 1);
    thumb_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    return TRUE;
}

// 0x002 : b.cond.W 0x2;
// 0x006 : b 0x6
// 0x008 : ldr pc, [pc, #0]
// 0x00c : .long 0x0
// 0x010 : remain code

// PAGE: A8-334
bool thumb_relocator_rewrite_B_T3(ThumbRelocator *self, const ARMInstruction *insn_ctx) {
    uint32_t insn1 = insn_ctx->insn1;
    uint32_t insn2 = insn_ctx->insn2;

    int S     = get_insn_sub(insn_ctx->insn1, 10, 1);
    int J2    = get_insn_sub(insn_ctx->insn2, 11, 1);
    int J1    = get_insn_sub(insn_ctx->insn2, 13, 1);
    int imm6  = get_insn_sub(insn_ctx->insn1, 0, 6);
    int imm11 = get_insn_sub(insn_ctx->insn2, 0, 11);
    uint32_t imm32 =
        imm11 << 1 | imm6 << (1 + 11) | J1 << (1 + 11 + 6) | J2 << (1 + 11 + 6 + 1) | S << (1 + 11 + 6 + 1 + 1);

    zz_addr_t target_address = insn_ctx->pc + imm32;
    zz_addr_t current_pc     = self->output->start_pc + self->output->insns_size;

    /* for align , simple solution, maybe the correct solution is get `ldr_reg_address` length and adjust the immediate
     * of `b_imm`. */
    if (current_pc % 4 == 0) {
        thumb_writer_put_nop(self->output);
    }
    thumb_writer_put_instruction(self->output, insn_ctx->insn1 & 0b1111101111000000);
    thumb_writer_put_instruction(self->output, (insn_ctx->insn2 & 0b1101000000000000) | 0b1);
    thumb_writer_put_b_imm(self->output, 0x6);
    thumb_writer_put_ldr_reg_address(self->output, ARM_REG_PC, target_address + 1);
    return TRUE;
}

// PAGE: A8-334
bool thumb_relocator_rewrite_B_T4(ThumbRelocator *self, const ARMInstruction *insn_ctx) {
    uint32_t insn1 = insn_ctx->insn1;
    uint32_t insn2 = insn_ctx->insn2;

    uint32_t S     = get_insn_sub(insn_ctx->insn1, 10 + 16, 1);
    uint32_t J2    = get_insn_sub(insn_ctx->insn2, 11, 1);
    uint32_t J1    = get_insn_sub(insn_ctx->insn2, 13, 1);
    uint32_t imm10 = get_insn_sub(insn_ctx->insn1, 0, 10);
    uint32_t imm11 = get_insn_sub(insn_ctx->insn2, 0, 11);
    uint32_t I1    = (~(J1 ^ S)) & 0x1;
    uint32_t I2    = (~(J2 ^ S)) & 0x1;
    uint32_t imm32 =
        imm11 << 1 | imm10 << (1 + 11) | I1 << (1 + 11 + 6) | I2 << (1 + 11 + 6 + 1) | S << (1 + 11 + 6 + 1 + 1);
    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm32;

    thumb_writer_put_ldr_reg_address(self->output, ARM_REG_PC, target_address + 1);
    thumb_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    return TRUE;
}

// PAGE: A8-348
bool thumb_relocator_rewrite_BLBLX_immediate_T1(ThumbRelocator *self, const ARMInstruction *insn_ctx) {
    uint32_t insn1 = insn_ctx->insn1;
    uint32_t insn2 = insn_ctx->insn2;

    uint32_t S     = get_insn_sub(insn_ctx->insn1, 10, 1);
    uint32_t J2    = get_insn_sub(insn_ctx->insn2, 11, 1);
    uint32_t J1    = get_insn_sub(insn_ctx->insn2, 13, 1);
    uint32_t imm10 = get_insn_sub(insn_ctx->insn1, 0, 10);
    uint32_t imm11 = get_insn_sub(insn_ctx->insn2, 0, 11);
    uint32_t I1    = (~(J1 ^ S)) & 0x1;
    uint32_t I2    = (~(J2 ^ S)) & 0x1;
    uint32_t imm32 =
        imm11 << 1 | imm10 << (1 + 11) | I1 << (1 + 11 + 6) | I2 << (1 + 11 + 6 + 1) | S << (1 + 11 + 6 + 1 + 1);
    zz_addr_t target_address;

    // CurrentInstrSet = thumb
    // targetInstrSet = arm
    target_address = insn_ctx->pc + imm32;

    thumb_writer_put_ldr_b_reg_address(self->output, ARM_REG_LR, insn_ctx->pc + 1);
    thumb_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    // register literal instruction
    thumb_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    thumb_writer_put_ldr_reg_address(self->output, ARM_REG_PC, target_address + 1);
    return TRUE;
}

// PAGE: A8-348
bool thumb_relocator_rewrite_BLBLX_T2(ThumbRelocator *self, const ARMInstruction *insn_ctx) {
    uint32_t insn1 = insn_ctx->insn1;
    uint32_t insn2 = insn_ctx->insn2;

    uint32_t S       = get_insn_sub(insn_ctx->insn1, 10, 1);
    uint32_t J2      = get_insn_sub(insn_ctx->insn2, 11, 1);
    uint32_t J1      = get_insn_sub(insn_ctx->insn2, 13, 1);
    uint32_t imm10_1 = get_insn_sub(insn_ctx->insn1, 0, 10);
    uint32_t imm10_2 = get_insn_sub(insn_ctx->insn2, 1, 10);
    uint32_t I1      = (~(J1 ^ S)) & 0x1;
    uint32_t I2      = (~(J2 ^ S)) & 0x1;

    uint32_t H = get_insn_sub(insn_ctx->insn2, 0, 1);

    int imm10_2_off = 2;
    int imm10_1_off = imm10_2_off + 10;
    int I1_off      = imm10_1_off + 10;
    int I2_off      = I1_off + 1;
    int S_off       = I2_off + 1;

    uint32_t sign_extend = (int)(S << 31) >> (31 - S_off);

    uint32_t imm32 = imm10_2 << imm10_2_off | imm10_1 << imm10_1_off | I1 << I1_off | I2 << I2_off | sign_extend;
    zz_addr_t target_address;

    // CurrentInstrSet = thumb
    // targetInstrSet = arm
    target_address = ALIGN_FLOOR(insn_ctx->pc, 4) + imm32;

    thumb_writer_put_ldr_b_reg_address(self->output, ARM_REG_LR, insn_ctx->pc + 1);
    thumb_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    thumb_writer_put_ldr_reg_address(self->output, ARM_REG_PC, target_address);
    thumb_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    return TRUE;
}

bool thumb_relocator_write_one(ThumbRelocator *self) {
    ARMInstruction *insn_ctx, **input_insnCTXs;
    ARMRelocatorInstruction *relocator_insn_ctx;
    relocator_insn_ctx = self->relocator_insnCTXs + self->relocated_insnCTXs_count;
    bool rewritten     = FALSE;

    if (self->needRelocateInputCount != self->doneRelocateInputCount) {
        input_insnCTXs                         = self->input->insnCTXs;
        insn_ctx                               = input_insnCTXs[self->doneRelocateInputCount];
        relocator_insn_ctx->origin_insn        = insn_ctx;
        relocator_insn_ctx->relocated_insnCTXs = self->output->insnCTXs + self->output->insnCTXs_count;
        relocator_insn_ctx->output_index_start = self->output->insnCTXs_count;
        self->doneRelocateInputCount++;
        self->relocated_insnCTXs_count++;
    } else
        return FALSE;

    switch (GetTHUMBInsnType(insn_ctx->insn1, insn_ctx->insn2)) {
    case THUMB_INS_CBNZ_CBZ:
        rewritten = thumb_relocator_rewrite_CBNZ_CBZ(self, insn_ctx);
        break;
    case THUMB_INS_ADD_register_T2:
        rewritten = thumb_relocator_rewrite_ADD_register_T2(self, insn_ctx);
        break;
    case THUMB_INS_LDR_literal_T1:
        rewritten = thumb_relocator_rewrite_LDR_literal_T1(self, insn_ctx);
        break;
    case THUMB_INS_LDR_literal_T2:
        rewritten = thumb_relocator_rewrite_LDR_literal_T2(self, insn_ctx);
        break;
    case THUMB_INS_ADR_T1:
        rewritten = thumb_relocator_rewrite_ADR_T1(self, insn_ctx);
        break;
    case THUMB_INS_ADR_T2:
        rewritten = thumb_relocator_rewrite_ADR_T2(self, insn_ctx);
        break;
    case THUMB_INS_ADR_T3:
        rewritten = thumb_relocator_rewrite_ADR_T3(self, insn_ctx);
        break;
    case THUMB_INS_B_T1:
        rewritten = thumb_relocator_rewrite_B_T1(self, insn_ctx);
        break;
    case THUMB_INS_B_T2:
        rewritten = thumb_relocator_rewrite_B_T2(self, insn_ctx);
        break;
    case THUMB_INS_B_T3:
        rewritten = thumb_relocator_rewrite_B_T3(self, insn_ctx);
        break;
    case THUMB_INS_B_T4:
        rewritten = thumb_relocator_rewrite_B_T4(self, insn_ctx);
        break;
    case THUMB_INS_BLBLX_immediate_T1:
        rewritten = thumb_relocator_rewrite_BLBLX_immediate_T1(self, insn_ctx);
        break;
    case THUMB_INS_BLBLX_immediate_T2:
        rewritten = thumb_relocator_rewrite_BLBLX_T2(self, insn_ctx);
        break;
    case THUMB_UNDEF:
        rewritten = FALSE;
        break;
    }

    if (!rewritten) {
        thumb_writer_put_bytes(self->output, (char *)&insn_ctx->insn, insn_ctx->size);
    } else {
    }

    relocator_insn_ctx->ouput_index_end = self->output->insnCTXs_count;
    relocator_insn_ctx->relocated_insnCTXs_count =
        relocator_insn_ctx->ouput_index_end - relocator_insn_ctx->output_index_start;

    return TRUE;
}

bool thumb_relocator_double_write(ThumbRelocator *self, zz_addr_t final_address) {
    assert(final_address % 2 == 0);
    ThumbAssemblerWriter *writer                                                            = self->output;
    char temp_codeslice[256]                                                                = {0};
    thumb_writer_reset(writer, temp_codeslice, final_adddress) self->doneRelocateInputCount = 0;
    self->relocated_insnCTXs_count                                                          = 0;
    self->literal_insnCTXs_count                                                            = 0;

    thumb_relocator_write_all(self);
    return true;
}