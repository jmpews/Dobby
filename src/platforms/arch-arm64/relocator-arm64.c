#include "relocator-arm64.h"
#include <stdlib.h>
#include <string.h>

#define MAX_RELOCATOR_INSTRUCIONS_SIZE 64

void zz_arm64_relocator_init(ZzARM64Relocator *relocator, zz_ptr_t input_code, ZzARM64AssemblerWriter *output) {
    relocator->inpos                       = 0;
    relocator->outpos                      = 0;
    relocator->output                      = output;
    relocator->input_start                 = input_code;
    relocator->input_cur                   = input_code;
    relocator->input_pc                    = (zz_addr_t)input_code;
    relocator->relocate_literal_insns_size = 0;
    relocator->try_relocated_length        = 0;

    relocator->input_insns =
        (ZzInstruction *)zz_malloc_with_zero(MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(ZzInstruction));
    relocator->output_insns =
        (ZzRelocateInstruction *)zz_malloc_with_zero(MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(ZzRelocateInstruction));
    relocator->relocate_literal_insns =
        (ZzLiteralInstruction **)zz_malloc_with_zero(MAX_LITERAL_INSN_SIZE * sizeof(ZzLiteralInstruction *));
}

void zz_arm64_relocator_free(ZzARM64Relocator *relocator) {
    free(relocator->input_insns);
    free(relocator->output_insns);
    free(relocator->relocate_literal_insns);
    free(relocator);
}

void zz_arm64_relocator_reset(ZzARM64Relocator *self, zz_ptr_t input_code, ZzARM64AssemblerWriter *output) {
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

zz_size_t zz_arm64_relocator_read_one(ZzARM64Relocator *self, ZzInstruction *instruction) {
    ZzInstruction *insn_ctx            = &self->input_insns[self->inpos];
    ZzRelocateInstruction *re_insn_ctx = &self->output_insns[self->inpos];

    re_insn_ctx->insn_ctx = insn_ctx;
    zz_arm64_reader_read_one_instruction(self->input_cur, insn_ctx);

    // switch (0) {}

    self->inpos++;

    if (instruction != NULL)
        *instruction = *insn_ctx;

    self->input_cur += insn_ctx->size;
    self->input_pc += insn_ctx->size;

    return self->input_cur - self->input_start;
}

zz_addr_t zz_arm64_relocator_get_insn_relocated_offset(ZzARM64Relocator *self, zz_addr_t address) {
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

void zz_arm64_relocator_relocate_writer(ZzARM64Relocator *relocator, zz_addr_t code_address) {
    ZzARM64AssemblerWriter *arm64_writer;
    arm64_writer = relocator->output;
    if (relocator->relocate_literal_insns_size) {
        int i;
        zz_addr_t *rebase_ptr;
        zz_addr_t literal_address, relocated_offset, relocated_address, *literal_address_ptr;
        for (i = 0; i < relocator->relocate_literal_insns_size; i++) {
            literal_address_ptr = relocator->relocate_literal_insns[i]->literal_address_ptr;
            literal_address     = *literal_address_ptr;
            relocated_offset    = zz_arm64_relocator_get_insn_relocated_offset(relocator, literal_address);
            if (relocated_offset) {
                relocated_address    = code_address + relocated_offset;
                *literal_address_ptr = relocated_address;
            }
        }
    }
}

void zz_arm64_relocator_write_all(ZzARM64Relocator *self) {
    int count                           = 0;
    int outpos                          = self->outpos;
    ZzARM64AssemblerWriter arm64_writer = *self->output;

    while (zz_arm64_relocator_write_one(self))
        count++;
}

void zz_arm64_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes) {
    int tmp_size = 0;
    zz_ptr_t target_addr;
    ZzInstruction insn_ctx;
    bool early_end = FALSE;
    target_addr    = (zz_ptr_t)address;

    do {
        zz_arm64_reader_read_one_instruction(target_addr, &insn_ctx);
        switch (GetARM64InsnType(insn_ctx.insn)) {
        case ARM64_INS_B:
            early_end = TRUE;
            break;
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

// PAGE: C6-673
static bool zz_arm64_relocator_rewrite_LDR_literal(ZzARM64Relocator *self, const ZzInstruction *insn_ctx,
                                                   ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn = insn_ctx->insn;
    // TODO: check opc == 10, with signed
    uint32_t imm19  = get_insn_sub(insn, 5, 19);
    uint64_t offset = imm19 << 2;

    zz_addr_t target_address;
    target_address = insn_ctx->pc + offset;
    int Rt_ndx     = get_insn_sub(insn, 0, 4);

    zz_arm64_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);
    zz_arm64_writer_put_ldr_reg_reg_offset(self->output, Rt_ndx, Rt_ndx, 0);

    return TRUE;
}

// PAGE: C6-535
static bool zz_arm64_relocator_rewrite_ADR(ZzARM64Relocator *self, const ZzInstruction *insn_ctx,
                                           ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t immhi = get_insn_sub(insn, 5, 19);
    uint32_t immlo = get_insn_sub(insn, 29, 2);
    uint64_t imm   = immhi << 2 | immlo;

    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm;
    int Rt_ndx     = get_insn_sub(insn, 0, 4);

    zz_arm64_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);

    return TRUE;
}

// PAGE: C6-536
static bool zz_arm64_relocator_rewrite_ADRP(ZzARM64Relocator *self, const ZzInstruction *insn_ctx,
                                            ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t immhi = get_insn_sub(insn, 5, 19);
    uint32_t immlo = get_insn_sub(insn, 29, 2);
    // 12 is PAGE-SIZE
    uint64_t imm = immhi << 2 << 12 | immlo << 12;

    zz_addr_t target_address;
    target_address = (insn_ctx->pc & 0xFFFFFFFFFFFFF000) + imm;
    int Rt_ndx     = get_insn_sub(insn, 0, 4);

    zz_arm64_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);

    return TRUE;
}

// PAGE: C6-550
static bool zz_arm64_relocator_rewrite_B(ZzARM64Relocator *self, const ZzInstruction *insn_ctx,
                                         ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm26 = get_insn_sub(insn, 0, 26);

    uint64_t offset = imm26 << 2;

    zz_addr_t target_address;
    target_address = insn_ctx->pc + offset;

    zz_arm64_writer_put_ldr_br_reg_address(self->output, ZZ_ARM64_REG_X17, target_address);

    return TRUE;
}

// PAGE: C6-560
static bool zz_arm64_relocator_rewrite_BL(ZzARM64Relocator *self, const ZzInstruction *insn_ctx,
                                          ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm26 = get_insn_sub(insn, 0, 26);

    uint64_t offset = imm26 << 2;

    zz_addr_t target_address;
    target_address = insn_ctx->pc + offset;

    zz_arm64_writer_put_ldr_blr_b_reg_address(self->output, ZZ_ARM64_REG_X17, target_address);
    ZzLiteralInstruction **literal_insn_ptr = &(self->relocate_literal_insns[self->relocate_literal_insns_size++]);
    zz_arm64_writer_put_ldr_br_reg_relocate_address(self->output, ZZ_ARM64_REG_X17, insn_ctx->pc + 4, literal_insn_ptr);

    return TRUE;
}

// 0x000 : b.cond 0x8;

// 0x004 : b 0x14

// 0x008 : ldr x17, [pc, #4]
// 0x00c : br x17
// 0x010 : .long 0x0
// 0x014 : .long 0x0

// 0x018 : remain code

// PAGE: C6-549
static bool zz_arm64_relocator_rewrite_B_cond(ZzARM64Relocator *self, const ZzInstruction *insn_ctx,
                                              ZzRelocateInstruction *re_insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm19 = get_insn_sub(insn, 5, 19);

    uint64_t offset = imm19 << 2;

    zz_addr_t target_address;
    target_address = insn_ctx->pc + offset;

    uint32_t cond = get_insn_sub(insn, 0, 4);

    zz_arm64_writer_put_b_cond_imm(self->output, cond, 0x8);
    zz_arm64_writer_put_b_imm(self->output, 0x14);
    zz_arm64_writer_put_ldr_br_reg_address(self->output, ZZ_ARM64_REG_X17, target_address);

    return TRUE;
}

bool zz_arm64_relocator_write_one(ZzARM64Relocator *self) {
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

    switch (GetARM64InsnType(insn_ctx->insn)) {
    case ARM64_INS_LDR_literal:
        rewritten = zz_arm64_relocator_rewrite_LDR_literal(self, insn_ctx, re_insn_ctx);
        break;
    case ARM64_INS_ADR:
        rewritten = zz_arm64_relocator_rewrite_ADR(self, insn_ctx, re_insn_ctx);
        break;
    case ARM64_INS_ADRP:
        rewritten = zz_arm64_relocator_rewrite_ADRP(self, insn_ctx, re_insn_ctx);
        break;
    case ARM64_INS_B:
        rewritten = zz_arm64_relocator_rewrite_B(self, insn_ctx, re_insn_ctx);
        break;
    case ARM64_INS_BL:
        rewritten = zz_arm64_relocator_rewrite_BL(self, insn_ctx, re_insn_ctx);
        break;
    case ARM64_INS_B_cond:
        rewritten = zz_arm64_relocator_rewrite_B_cond(self, insn_ctx, re_insn_ctx);
        break;
    default:
        rewritten = FALSE;
        break;
    }
    if (!rewritten)
        zz_arm64_writer_put_bytes(self->output, (char *)&insn_ctx->insn, insn_ctx->size);
    re_insn_ctx->relocated_length =
        (zz_addr_t)self->output->pc - (zz_addr_t)self->output->base - (zz_addr_t)re_insn_ctx->relocated_offset;
    return TRUE;
}