#include "relocator-arm64.h"
#include <stdlib.h>
#include <string.h>

#define MAX_RELOCATOR_INSTRUCIONS_SIZE 64


void zz_arm64_relocator_init(ZzARM64Relocator *relocator, ZzARM64Reader *input, ZzARM64AssemblerWriter *output) {
    memset(relocator, 0, sizeof(ZzARM64Relocator));
    relocator->inpos = 0;
    relocator->outpos = 0;
    relocator->input = input;
    relocator->output = output;
    relocator->try_relocated_length = 0;

//    relocator->literal_insns =
//        (ZzARM64Instruction **)zz_malloc_with_zero(MAX_LITERAL_INSN_SIZE * sizeof(ZzARM64Instruction *));
}

void zz_arm64_relocator_free(ZzARM64Relocator *relocator) {

    zz_arm64_reader_free(relocator->input);
    zz_arm64_writer_free(relocator->output);
    free(relocator);
}

void
zz_arm64_relocator_reset(ZzARM64Relocator *self, ZzARM64Reader *input, ZzARM64AssemblerWriter *output) {
    self->inpos = 0;
    self->outpos = 0;
    self->input = input;
    self->output = output;
    self->literal_insn_size = 0;
    self->try_relocated_length = 0;
}

zz_size_t zz_arm64_relocator_read_one(ZzARM64Relocator *self, ZzARM64Instruction *instruction) {
    ZzARM64Instruction *insn_ctx;

    zz_arm64_reader_read_one_instruction(self->input);

    // switch (1) {}

    self->inpos++;

    if (instruction != NULL)
        *instruction = *insn_ctx;
}



void zz_arm64_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes) {
    int tmp_size = 0;
    bool early_end = FALSE;
    zz_addr_t target_addr = (zz_addr_t) address;
    ZzARM64Instruction *insn_ctx;
    ZzARM64Reader *reader = zz_arm64_reader_new(address);

    do {
        insn_ctx = zz_arm64_reader_read_one_instruction(reader);
        switch (GetARM64InsnType(insn_ctx->insn)) {
        case ARM64_INS_B:
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

    zz_arm64_reader_free(reader);
    return;
}

void zz_arm64_relocator_relocate_writer(ZzARM64Relocator *relocator, zz_addr_t final_relocate_address) {
    ZzARM64AssemblerWriter *arm_writer;
    arm_writer = relocator->output;
    if (relocator->literal_insn_size) {
        zz_size_t literal_offset;
        zz_addr_t *literal_target_address_ptr;
        for (int i = 0; i < relocator->literal_insn_size; i++) {
            literal_target_address_ptr = (zz_addr_t *)relocator->literal_insns[i]->address;
            *literal_target_address_ptr += final_relocate_address;

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

void zz_arm64_relocator_register_literal_insn(ZzARM64Relocator *self, ZzARM64Instruction *insn_ctx) {
    self->literal_insns[self->literal_insn_size++] = insn_ctx;
    // convert the temportary absolute address with offset.
    zz_addr_t *temp_address = (zz_addr_t  *)insn_ctx->address;
    *temp_address = insn_ctx->pc - self->output->start_pc;
}

// PAGE: C6-673
static bool zz_arm64_relocator_rewrite_LDR_literal(ZzARM64Relocator *self, const ZzARM64Instruction *insn_ctx
                                                   ) {
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
static bool zz_arm64_relocator_rewrite_ADR(ZzARM64Relocator *self, const ZzARM64Instruction *insn_ctx
                                           ) {
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
static bool zz_arm64_relocator_rewrite_ADRP(ZzARM64Relocator *self, const ZzARM64Instruction *insn_ctx
                                            ) {
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
static bool zz_arm64_relocator_rewrite_B(ZzARM64Relocator *self, const ZzARM64Instruction *insn_ctx
                                         ) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm26 = get_insn_sub(insn, 0, 26);

    uint64_t offset = imm26 << 2;

    zz_addr_t target_address;
    target_address = insn_ctx->pc + offset;

    zz_arm64_writer_put_ldr_br_reg_address(self->output, ZZ_ARM64_REG_X17, target_address);

    return TRUE;
}

// PAGE: C6-560
static bool zz_arm64_relocator_rewrite_BL(ZzARM64Relocator *self, const ZzARM64Instruction *insn_ctx
                                          ) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm26 = get_insn_sub(insn, 0, 26);

    uint64_t offset = imm26 << 2;

    zz_addr_t target_address;
    target_address = insn_ctx->pc + offset;

    zz_arm64_writer_put_ldr_blr_b_reg_address(self->output, ZZ_ARM64_REG_X17, target_address);
    zz_arm64_writer_put_ldr_br_reg_address(self->output, ZZ_ARM64_REG_X17, insn_ctx->pc + 4);
    // register literal instruction
    if(target_address > self->input->start_pc && target_address < (self->input->start_pc+ self->input->size))
        zz_arm64_relocator_register_literal_insn(self, self->output->insns[self->output->insn_size - 1]);

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
static bool zz_arm64_relocator_rewrite_B_cond(ZzARM64Relocator *self, const ZzARM64Instruction *insn_ctx
                                              ) {
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
    ZzARM64Instruction *insn_ctx, **input_insns;
    bool rewritten = FALSE;

    if (self->inpos != self->outpos) {
        input_insns = self->input->insns;
        insn_ctx    = input_insns[self->outpos];
        self->outpos++;
    } else
        return FALSE;
    switch (GetARM64InsnType(insn_ctx->insn)) {
    case ARM64_INS_LDR_literal:
        rewritten = zz_arm64_relocator_rewrite_LDR_literal(self, insn_ctx);
        break;
    case ARM64_INS_ADR:
        rewritten = zz_arm64_relocator_rewrite_ADR(self, insn_ctx);
        break;
    case ARM64_INS_ADRP:
        rewritten = zz_arm64_relocator_rewrite_ADRP(self, insn_ctx);
        break;
    case ARM64_INS_B:
        rewritten = zz_arm64_relocator_rewrite_B(self, insn_ctx);
        break;
    case ARM64_INS_BL:
        rewritten = zz_arm64_relocator_rewrite_BL(self, insn_ctx);
        break;
    case ARM64_INS_B_cond:
        rewritten = zz_arm64_relocator_rewrite_B_cond(self, insn_ctx);
        break;
    default:
        rewritten = FALSE;
        break;
    }
    if (!rewritten) {
        zz_arm64_writer_put_bytes(self->output, (char *) &insn_ctx->insn, insn_ctx->size);
    } else {

    }
    return TRUE;
}