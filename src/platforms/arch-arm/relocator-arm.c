#include "relocator-arm.h"

#include <stdlib.h>
#include <string.h>

#define MAX_RELOCATOR_INSTRUCIONS_SIZE 64

void zz_arm_relocator_init(ZzARMRelocator *relocator, zz_ptr_t input_code, ZzARMAssemblerWriter *output) {
    relocator->inpos                       = 0;
    relocator->outpos                      = 0;
    relocator->input_start                 = input_code;
    relocator->input_cur                   = input_code;
    relocator->input_pc                    = (zz_addr_t)input_code;
    relocator->output                      = output;
    relocator->relocate_literal_insns_size = 0;
    relocator->try_relocated_length        = 0;

    relocator->input_insns =
        (ZzInstruction *)zz_malloc_with_zero(MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(ZzInstruction));
    relocator->output_insns =
        (ZzRelocateInstruction *)zz_malloc_with_zero(MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(ZzRelocateInstruction));
    relocator->relocate_literal_insns =
        (ZzLiteralInstruction **)zz_malloc_with_zero(MAX_LITERAL_INSN_SIZE * sizeof(ZzLiteralInstruction *));
}

void zz_arm_relocator_free(ZzARMRelocator *relocator) {
    free(relocator->input_insns);
    free(relocator->output_insns);
    free(relocator->relocate_literal_insns);
    free(relocator);
}

void zz_arm_relocator_reset(ZzARMRelocator *self, zz_ptr_t input_code, ZzARMAssemblerWriter *output) {
    self->input_cur                   = input_code;
    self->input_start                 = input_code;
    self->input_pc                    = (zz_addr_t)input_code;
    self->inpos                       = 0;
    self->outpos                      = 0;
    self->output                      = output;
    self->relocate_literal_insns_size = 0;
    self->try_relocated_length        = 0;

    memset(self->input_insns, 0, MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(ZzInstruction));
    memset(self->output_insns, 0, MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(ZzRelocateInstruction));
    memset(self->relocate_literal_insns, 0, MAX_LITERAL_INSN_SIZE * sizeof(ZzLiteralInstruction *));
}

zz_size_t zz_arm_relocator_read_one(ZzARMRelocator *self, ZzInstruction *instruction) {
    ZzInstruction *insn_ctx            = &self->input_insns[self->inpos];
    ZzRelocateInstruction *re_insn_ctx = &self->output_insns[self->inpos];

    re_insn_ctx->insn_ctx = insn_ctx;
    zz_arm_reader_read_one_instruction(self->input_cur, insn_ctx);

    // switch (1) {}

    self->inpos++;

    if (instruction != NULL)
        *instruction = *insn_ctx;

    self->input_cur += insn_ctx->size;
    self->input_pc += insn_ctx->size;

    return self->input_cur - self->input_start;
}
void zz_arm_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes) {
    int tmp_size = 0;
    zz_ptr_t target_addr;
    ZzInstruction insn_ctx;
    bool early_end = FALSE;
    target_addr    = (zz_ptr_t)address;

    do {
        zz_arm_reader_read_one_instruction(target_addr, &insn_ctx);
        switch (GetARMInsnType(insn_ctx.insn)) {
        case ARM_INS_B_A1: {
            uint32_t cond = get_insn_sub(insn_ctx.insn, 28, 4);
            if (cond == 0xE)
                early_end = TRUE;
        }; break;
        default:;
        }
        tmp_size += insn_ctx.size;
        target_addr = target_addr + insn_ctx.size;
    } while (tmp_size < min_bytes);

    if (early_end) {
        *max_bytes = tmp_size;
    }
    return;
}

zz_addr_t zz_arm_relocator_get_insn_relocated_offset(ZzARMRelocator *self, zz_addr_t address) {
    const ZzInstruction *insn_ctx;
    const ZzRelocateInstruction *re_insn_ctx;
    int i;
    for (i = 0; i < self->inpos; i++) {
        re_insn_ctx = &self->output_insns[i];
        insn_ctx    = re_insn_ctx->insn_ctx;
        if (insn_ctx->address == address && re_insn_ctx->relocated_offset) {
            return re_insn_ctx->relocated_offset;
        }
    }
    return 0;
}

void zz_arm_relocator_relocate_writer(ZzARMRelocator *relocator, zz_addr_t code_address) {
    ZzARMAssemblerWriter *arm_writer;
    arm_writer = relocator->output;
    if (relocator->relocate_literal_insns_size) {
        int i;
        zz_addr_t literal_address, relocated_offset, relocated_address, *literal_address_ptr;
        for (i = 0; i < relocator->relocate_literal_insns_size; i++) {
            literal_address_ptr = (zz_addr_t *)relocator->relocate_literal_insns[i]->literal_address_ptr;
            literal_address     = *literal_address_ptr;
            relocated_offset    = zz_arm_relocator_get_insn_relocated_offset(relocator, literal_address);
            if (relocated_offset) {
                relocated_address    = code_address + relocated_offset;
                *literal_address_ptr = relocated_address;
            }
        }
    }
}

void zz_arm_relocator_write_all(ZzARMRelocator *self) {
    int count                       = 0;
    int outpos                      = self->outpos;
    ZzARMAssemblerWriter arm_writer = *self->output;

    while (zz_arm_relocator_write_one(self))
        count++;
}

// PAGE: A8-312
static bool zz_arm_relocator_rewrite_ADD_register_A1(ZzARMRelocator *self, const ZzInstruction *insn_ctx,
                                                     ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn = insn_ctx->insn;

    uint32_t Rn_ndx, Rd_ndx, Rm_ndx;
    Rn_ndx = get_insn_sub(insn, 16, 4);
    Rd_ndx = get_insn_sub(insn, 12, 4);
    Rm_ndx = get_insn_sub(insn, 0, 4);

    if (Rn_ndx != ZZ_ARM_REG_PC) {
        return FALSE;
    }
    // push R7
    zz_arm_writer_put_push_reg(self->output, ZZ_ARM_REG_R7);
    zz_arm_writer_put_ldr_b_reg_address(self->output, ZZ_ARM_REG_R7, insn_ctx->pc);
    zz_arm_writer_put_instruction(self->output, (insn & 0xFFF0FFFF) | ZZ_ARM_REG_R7 << 16);
    // pop R7
    zz_arm_writer_put_pop_reg(self->output, ZZ_ARM_REG_R7);
    return TRUE;
}

// PAGE: A8-410
static bool zz_arm_relocator_rewrite_LDR_literal_A1(ZzARMRelocator *self, const ZzInstruction *insn_ctx,
                                                    ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm12 = get_insn_sub(insn, 0, 12);
    uint32_t imm32 = imm12;
    bool add       = get_insn_sub(insn, 7 + 16, 1) == 1;
    zz_addr_t target_address;
    if (add)
        target_address = insn_ctx->pc + imm32;
    else
        target_address = insn_ctx->pc - imm32;
    int Rt_ndx = get_insn_sub(insn, 12, 4);

    zz_arm_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);
    zz_arm_writer_put_ldr_reg_reg_imm(self->output, Rt_ndx, Rt_ndx, 0);

    return TRUE;
}

// PAGE: A8-322
static bool zz_arm_relocator_rewrite_ADR_A1(ZzARMRelocator *self, const ZzInstruction *insn_ctx,
                                            ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm12 = get_insn_sub(insn, 0, 12);
    uint32_t imm32 = imm12;
    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm32;
    int Rt_ndx     = get_insn_sub(insn, 12, 4);

    zz_arm_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);

    return TRUE;
}

// PAGE: A8-322
static bool zz_arm_relocator_rewrite_ADR_A2(ZzARMRelocator *self, const ZzInstruction *insn_ctx,
                                            ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm12 = get_insn_sub(insn, 0, 12);
    uint32_t imm32 = imm12;
    zz_addr_t target_address;
    target_address = insn_ctx->pc - imm32;
    int Rt_ndx     = get_insn_sub(insn, 12, 4);

    zz_arm_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);

    return TRUE;
}

// 0x000 : b.cond 0x0;
// 0x004 : b 0x4
// 0x008 : ldr pc, [pc, #0]
// 0x00c : .long 0x0
// 0x010 : remain code

// PAGE: A8-334
static bool zz_arm_relocator_rewrite_B_A1(ZzARMRelocator *self, const ZzInstruction *insn_ctx,
                                          ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm24 = get_insn_sub(insn, 0, 24);
    uint32_t imm32 = imm24 << 2;
    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm32;

    zz_arm_writer_put_instruction(self->output, (insn & 0xFF000000) | 0);
    zz_arm_writer_put_b_imm(self->output, 0x4);
    zz_arm_writer_put_ldr_reg_address(self->output, ZZ_ARM_REG_PC, target_address);

    return TRUE;
}

// 0x000 : bl.cond 0x0;

// 0x004 : b 0x10

// 0x008 : ldr lr, [pc, #0]
// 0x00c : b 0x0
// 0x010 : .long 0x0

// 0x014 : ldr pc, [pc, #0]
// 0x018 : .long 0x0

// 0x01c : remain code

// PAGE: A8-348
static bool zz_arm_relocator_rewrite_BLBLX_immediate_A1(ZzARMRelocator *self, const ZzInstruction *insn_ctx,
                                                        ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm24 = get_insn_sub(insn, 0, 24);
    uint32_t imm32 = imm24 << 2;
    zz_addr_t target_address;
    target_address = ALIGN_4(insn_ctx->pc) + imm32;

    // CurrentInstrSet = thumb
    // targetInstrSet = arm

    // convert 'bl' to 'b', but save 'cond'
    zz_arm_writer_put_instruction(self->output, (insn & 0xF0000000) | 0b1010 << 24 | 0);

    ZzARMAssemblerWriter ouput_bak = *self->output;

    zz_arm_writer_put_b_imm(self->output, 0);
    ZzLiteralInstruction **literal_insn_ptr = &(self->relocate_literal_insns[self->relocate_literal_insns_size++]);
    zz_arm_writer_put_ldr_b_reg_relocate_address(self->output, ZZ_ARM_REG_LR, insn_ctx->pc - 4, literal_insn_ptr);
    zz_arm_writer_put_ldr_reg_address(self->output, ZZ_ARM_REG_PC, target_address);

    // overwrite `zz_arm_writer_put_b_imm`
    zz_arm_writer_put_b_imm(&ouput_bak, self->output->pc - ouput_bak.pc - 8);
    return TRUE;
}

// PAGE: A8-348
static bool zz_arm_relocator_rewrite_BLBLX_immediate_A2(ZzARMRelocator *self, const ZzInstruction *insn_ctx,
                                                        ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t H     = get_insn_sub(insn, 24, 1);
    uint32_t imm24 = get_insn_sub(insn, 0, 24);
    uint32_t imm32 = (imm24 << 2) | (H << 1);
    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm32;

    ZzLiteralInstruction **literal_insn_ptr = &(self->relocate_literal_insns[self->relocate_literal_insns_size++]);
    zz_arm_writer_put_ldr_b_reg_relocate_address(self->output, ZZ_ARM_REG_LR, insn_ctx->pc - 4, literal_insn_ptr);
    zz_arm_writer_put_ldr_reg_address(self->output, ZZ_ARM_REG_PC, target_address);

    return TRUE;
}

bool zz_arm_relocator_write_one(ZzARMRelocator *self) {
    const ZzInstruction *insn_ctx;
    ZzRelocateInstruction *re_insn_ctx;
    bool rewritten = FALSE;

    if (self->inpos != self->outpos) {
        insn_ctx    = &self->input_insns[self->outpos];
        re_insn_ctx = &self->output_insns[self->outpos];

        self->outpos++;
    } else
        return FALSE;

    re_insn_ctx->relocated_offset = (zz_addr_t)self->output->pc - (zz_addr_t)self->output->base;

    switch (GetARMInsnType(insn_ctx->insn)) {
    case ARM_INS_ADD_register_A1:
        rewritten = zz_arm_relocator_rewrite_ADD_register_A1(self, insn_ctx, re_insn_ctx);
        break;
    case ARM_INS_LDR_literal_A1:
        rewritten = zz_arm_relocator_rewrite_LDR_literal_A1(self, insn_ctx, re_insn_ctx);
        break;
    case ARM_INS_ADR_A1:
        rewritten = zz_arm_relocator_rewrite_ADR_A1(self, insn_ctx, re_insn_ctx);
        break;
    case ARM_INS_ADR_A2:
        rewritten = zz_arm_relocator_rewrite_ADR_A2(self, insn_ctx, re_insn_ctx);
        break;
    case ARM_INS_B_A1:
        rewritten = zz_arm_relocator_rewrite_B_A1(self, insn_ctx, re_insn_ctx);
        break;
    case ARM_INS_BLBLX_immediate_A1:
        rewritten = zz_arm_relocator_rewrite_BLBLX_immediate_A1(self, insn_ctx, re_insn_ctx);
        break;
    case ARM_INS_BLBLX_immediate_A2:
        rewritten = zz_arm_relocator_rewrite_BLBLX_immediate_A2(self, insn_ctx, re_insn_ctx);
        break;
    case ARM_UNDEF:
        rewritten = FALSE;
        break;
    }
    if (!rewritten)
        zz_arm_writer_put_bytes(self->output, (char *)&insn_ctx->insn, insn_ctx->size);

    re_insn_ctx->relocated_length =
        (zz_addr_t)self->output->pc - (zz_addr_t)self->output->base - (zz_addr_t)re_insn_ctx->relocated_offset;
    return TRUE;
}
