#include "relocator-arm64.h"
#include "ARM64AssemblyCore.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RELOCATOR_INSTRUCIONS_SIZE 64

void arm64_relocator_init(ARM64Relocator *relocator, ARM64AssemblyReader *input, ARM64AssemblyrWriter *output) {
    memset(relocator, 0, sizeof(ARM64Relocator));
    relocator->needRelocateInputCount = 0;
    relocator->doneRelocateInputCount = 0;
    relocator->input                  = input;
    relocator->output                 = output;
    relocator->try_relocated_length   = 0;

    //    relocator->literal_insnCTXs =
    //        (ARM64InstructionCTX **)malloc0(MAX_LITERAL_INSN_SIZE * sizeof(ARM64InstructionCTX *));
}

void arm64_relocator_free(ARM64Relocator *relocator) {
    arm64_reader_free(relocator->input);
    arm64_writer_free(relocator->output);
    free(relocator);
}

void arm64_relocator_reset(ARM64Relocator *self, ARM64AssemblyReader *input, ARM64AssemblyrWriter *output) {
    self->needRelocateInputCount = 0;
    self->doneRelocateInputCount = 0;
    self->input                  = input;
    self->output                 = output;
    self->literal_insnCTXs_count = 0;
    self->try_relocated_length   = 0;
}

void arm64_relocator_read_one(ARM64Relocator *self, ARM64InstructionCTX *instruction) {
    ARM64InstructionCTX *insn_ctx;
    insn_ctx = arm64_reader_read_one_instruction(self->input);

    // switch (1) {}

    self->needRelocateInputCount++;

    if (instruction != NULL)
        *instruction = *insn_ctx;
}

void arm64_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes) {
    int tmp_size          = 0;
    bool early_end        = FALSE;
    zz_addr_t target_addr = (zz_addr_t)address;
    ARM64InstructionCTX *insn_ctx;
    ARM64AssemblyReader *reader = arm64_reader_new(address);

    do {
        insn_ctx = arm64_reader_read_one_instruction(reader);
        switch (getInstType(insn_ctx->insn)) {
        case BImm:
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

    arm64_reader_free(reader);
    return;
}

static ARM64RelocatorInstruction *arm64_relocator_get_relocator_insn_with_address(ARM64Relocator *self,
                                                                                  zz_addr_t insn_address) {
    for (int i = 0; i < self->relocated_insnCTXs_count; ++i) {
        if ((self->relocator_insnCTXs[i].origin_insn->pc) == insn_address) {
            return &self->relocator_insnCTXs[i];
        }
    }
    return NULL;
}

void arm64_relocator_relocate_writer(ARM64Relocator *relocator, zz_addr_t final_relocate_address) {
    ARM64RelocatorInstruction *relocated_insn;
    if (relocator->literal_insnCTXs_count) {
        zz_addr_t *literal_target_address_ptr;
        for (int i = 0; i < relocator->literal_insnCTXs_count; i++) {
            literal_target_address_ptr = (zz_addr_t *)relocator->literal_insnCTXs[i]->address;
            // literal instruction in the range of instructions-need-fix
            if (*literal_target_address_ptr > relocator->input->start_pc &&
                *literal_target_address_ptr < (relocator->input->start_pc + relocator->input->insns_size)) {
                relocated_insn =
                    arm64_relocator_get_relocator_insn_with_address(relocator, *literal_target_address_ptr);
                assert(relocated_insn);
                *literal_target_address_ptr =
                    (*relocated_insn->relocated_insnCTXs)->pc - relocator->output->start_pc + final_relocate_address;
            }
        }
    }
}

void arm64_relocator_write_all(ARM64Relocator *self) {
    int count                   = 0;
    int doneRelocateInputCount  = self->doneRelocateInputCount;
    ARM64AssemblyrWriter writer = *self->output;

    while (arm64_relocator_write_one(self))
        count++;
}

static void arm64_relocator_register_literal_insn(ARM64Relocator *self, ARM64InstructionCTX *insn_ctx) {
    self->literal_insnCTXs[self->literal_insnCTXs_count++] = insn_ctx;
}

static bool arm64_relocator_rewrite_LoadLiteral(ARM64Relocator *self, const ARM64InstructionCTX *insn_ctx) {
    ARM64AssemblyrWriter *writer = self->output;
    uint32_t Rt, label;
    int index;
    zz_addr_t target_address;
    Rt             = get_insn_sub(insn_ctx->insn, 0, 5);
    label          = get_insn_sub(insn_ctx->insn, 5, 19);
    target_address = (label << 2) + insn_ctx->pc;

    /*
        0x1000: ldr Rt, #0x8
        0x1004: b #0xc
        0x1008: .long 0x4321
        0x100c: .long 0x8765
        0x1010: ldr Rt, Rt
    */
    arm64_writer_put_ldr_reg_imm(writer, Rt, 0x8);
    arm64_writer_put_b_imm(writer, 0xc);
    arm64_relocator_register_literal_insn(self, writer->insnCTXs[self->output->insnCTXs_count]);
    arm64_writer_put_bytes(writer, (zz_ptr_t)&target_address, sizeof(target_address));
    arm64_writer_put_ldr_reg_reg_offset(writer, Rt, Rt, 0);

    return true;
};

static bool arm64_relocator_rewrite_BaseCmpBranch(ARM64Relocator *self, const ARM64InstructionCTX *insn_ctx) {
    ARM64AssemblyrWriter *writer = self->output;
    uint32_t target;
    uint32_t inst32;
    zz_addr_t target_address;

    inst32 = insn_ctx->insn;

    target         = get_insn_sub(inst32, 5, 19);
    target_address = (target << 2) + insn_ctx->pc;

    target = 0x8 >> 2;
    BIT32SET(&inst32, 5, 19, target);
    arm64_writer_put_instruction(writer, inst32);

    arm64_writer_put_b_imm(writer, 0x14);
    arm64_writer_put_ldr_reg_imm(writer, ARM64_REG_X17, 0x8);
    arm64_writer_put_br_reg(writer, ARM64_REG_X17);
    arm64_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count]);
    arm64_writer_put_bytes(writer, (zz_ptr_t)&target_address, sizeof(zz_ptr_t));
    return true;
};

static bool arm64_relocator_rewrite_BranchCond(ARM64Relocator *self, const ARM64InstructionCTX *insn_ctx) {
    ARM64AssemblyrWriter *writer = self->output;
    uint32_t target;
    uint32_t inst32;
    zz_addr_t target_address;

    inst32 = insn_ctx->insn;

    target         = get_insn_sub(inst32, 5, 19);
    target_address = (target << 2) + insn_ctx->pc;

    target = 0x8 >> 2;
    BIT32SET(&inst32, 5, 19, target);
    arm64_writer_put_instruction(writer, inst32);

    arm64_writer_put_b_imm(writer, 0x14);
    arm64_writer_put_ldr_reg_imm(writer, ARM64_REG_X17, 0x8);
    arm64_writer_put_br_reg(writer, ARM64_REG_X17);
    arm64_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count]);
    arm64_writer_put_bytes(writer, (zz_ptr_t)&target_address, sizeof(zz_ptr_t));
    return true;
};

static bool arm64_relocator_rewrite_B(ARM64Relocator *self, const ARM64InstructionCTX *insn_ctx) {
    ARM64AssemblyrWriter *writer = self->output;
    uint32_t addr;
    zz_addr_t target_address;

    addr = get_insn_sub(insn_ctx->insn, 0, 26);

    target_address = (addr << 2) + insn_ctx->pc;

    arm64_writer_put_ldr_reg_imm(writer, ARM64_REG_X17, 0x8);
    arm64_writer_put_br_reg(writer, ARM64_REG_X17);
    arm64_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count]);
    arm64_writer_put_bytes(writer, (zz_ptr_t)&target_address, sizeof(zz_ptr_t));

    return TRUE;
}

static bool arm64_relocator_rewrite_BL(ARM64Relocator *self, const ARM64InstructionCTX *insn_ctx) {
    ARM64AssemblyrWriter *writer = self->output;
    uint32_t op, addr;
    zz_addr_t target_address, next_pc_address;

    addr = get_insn_sub(insn_ctx->insn, 0, 26);

    target_address  = (addr << 2) + insn_ctx->pc;
    next_pc_address = insn_ctx->pc + 4;

    arm64_writer_put_ldr_reg_imm(writer, ARM64_REG_X17, 0xc);
    arm64_writer_put_blr_reg(writer, ARM64_REG_X17);
    arm64_writer_put_b_imm(writer, 0xc);
    arm64_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count]);
    arm64_writer_put_bytes(writer, (zz_ptr_t)&target_address, sizeof(zz_ptr_t));

    arm64_writer_put_ldr_reg_imm(writer, ARM64_REG_X17, 0x8);
    arm64_writer_put_br_reg(writer, ARM64_REG_X17);
    arm64_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count]);
    arm64_writer_put_bytes(writer, (zz_ptr_t)&next_pc_address, sizeof(zz_ptr_t));

    return TRUE;
}

#if 0
// ###### ATTENTION ######
// refer ARM64 Architecture Manual
// PAGE: C6-673
static bool arm64_relocator_rewrite_LDR_literal(ARM64Relocator *self, const ARM64InstructionCTX *insn_ctx) {
    uint32_t insn = insn_ctx->insn;
    // TODO: check opc == 10, with signed
    uint32_t imm19  = get_insn_sub(insn, 5, 19);
    uint64_t offset = imm19 << 2;

    zz_addr_t target_address;
    target_address = insn_ctx->pc + offset;
    int Rt_ndx     = get_insn_sub(insn, 0, 4);

    arm64_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);
    arm64_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    arm64_writer_put_ldr_reg_reg_offset(self->output, Rt_ndx, Rt_ndx, 0);

    return TRUE;
}

// PAGE: C6-535
static bool arm64_relocator_rewrite_ADR(ARM64Relocator *self, const ARM64InstructionCTX *insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t immhi = get_insn_sub(insn, 5, 19);
    uint32_t immlo = get_insn_sub(insn, 29, 2);
    uint64_t imm   = immhi << 2 | immlo;

    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm;
    int Rt_ndx     = get_insn_sub(insn, 0, 4);

    arm64_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);

    return TRUE;
}

// PAGE: C6-536
static bool arm64_relocator_rewrite_ADRP(ARM64Relocator *self, const ARM64InstructionCTX *insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t immhi = get_insn_sub(insn, 5, 19);
    uint32_t immlo = get_insn_sub(insn, 29, 2);
    // 12 is PAGE-SIZE
    uint64_t imm = immhi << 2 << 12 | immlo << 12;

    zz_addr_t target_address;
    target_address = (insn_ctx->pc & 0xFFFFFFFFFFFFF000) + imm;
    int Rt_ndx     = get_insn_sub(insn, 0, 4);

    arm64_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);

    return TRUE;
}

// PAGE: C6-550
static bool arm64_relocator_rewrite_B(ARM64Relocator *self, const ARM64InstructionCTX *insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm26 = get_insn_sub(insn, 0, 26);

    uint64_t offset = imm26 << 2;

    zz_addr_t target_address;
    target_address = insn_ctx->pc + offset;

    arm64_writer_put_ldr_br_reg_address(self->output, ARM64_REG_X17, target_address);
    arm64_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);

    return TRUE;
}

// PAGE: C6-560
static bool arm64_relocator_rewrite_BL(ARM64Relocator *self, const ARM64InstructionCTX *insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm26 = get_insn_sub(insn, 0, 26);

    uint64_t offset = imm26 << 2;

    zz_addr_t target_address;
    target_address = insn_ctx->pc + offset;

    arm64_writer_put_ldr_blr_b_reg_address(self->output, ARM64_REG_X17, target_address);
    arm64_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    arm64_writer_put_ldr_br_reg_address(self->output, ARM64_REG_X17, insn_ctx->pc + 4);
    arm64_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);

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
static bool arm64_relocator_rewrite_B_cond(ARM64Relocator *self, const ARM64InstructionCTX *insn_ctx) {
    uint32_t insn  = insn_ctx->insn;
    uint32_t imm19 = get_insn_sub(insn, 5, 19);

    uint64_t offset = imm19 << 2;

    zz_addr_t target_address;
    target_address = insn_ctx->pc + offset;

    uint32_t cond = get_insn_sub(insn, 0, 4);

    arm64_writer_put_b_cond_imm(self->output, cond, 0x8);
    arm64_writer_put_b_imm(self->output, 0x14);
    arm64_writer_put_ldr_br_reg_address(self->output, ARM64_REG_X17, target_address);
    arm64_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);

    return TRUE;
}

#endif

bool arm64_relocator_write_one(ARM64Relocator *self) {
    ARM64InstructionCTX *insn_ctx, **input_insnCTXs;
    ARM64RelocatorInstruction *relocator_insn_ctx;
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
    switch (getInstType(insn_ctx->insn)) {
    case LoadLiteral:
        rewritten = arm64_relocator_rewrite_LoadLiteral(self, insn_ctx);
        break;
    case BaseCmpBranch:
        rewritten = arm64_relocator_rewrite_BaseCmpBranch(self, insn_ctx);
        break;
    case BranchCond:
        rewritten = arm64_relocator_rewrite_BranchCond(self, insn_ctx);
        break;
    case B:
        rewritten = arm64_relocator_rewrite_B(self, insn_ctx);
        break;
    case BL:
        rewritten = arm64_relocator_rewrite_BL(self, insn_ctx);
        break;

    default:
        rewritten = FALSE;
        break;
    }
    if (!rewritten) {
        arm64_writer_put_bytes(self->output, (char *)&insn_ctx->insn, insn_ctx->size);
    } else {
    }

    relocator_insn_ctx->ouput_index_end = self->output->insnCTXs_count;
    relocator_insn_ctx->relocated_insnCTXs_count =
        relocator_insn_ctx->ouput_index_end - relocator_insn_ctx->output_index_start;

    return TRUE;
}

bool arm64_relocator_double_write(ARM64Relocator *self, zz_addr_t final_address) {
    assert(final_address % 4 == 0);
    ARM64AssemblyrWriter *writer = self->output;

    int origin_insns_size = writer->insns_size;

    arm64_writer_reset(writer, writer->insns_buffer, final_address);
    self->doneRelocateInputCount   = 0;
    self->relocated_insnCTXs_count = 0;
    self->literal_insnCTXs_count   = 0;

    arm64_relocator_write_all(self);

    zz_addr_t not_relocate_insns_buffer = writer->insns_buffer + writer->insns_size;

    arm64_writer_put_bytes(writer, (zz_ptr_t)not_relocate_insns_buffer, origin_insns_size - writer->insns_size);

    return true;
}
