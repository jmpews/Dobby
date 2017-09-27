/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "relocator-arm.h"
#include <string.h>

#define MAX_RELOCATOR_INSTRUCIONS_SIZE 64

void zz_arm_relocator_init(ZzArmRelocator *relocator, zpointer input_code, ZzArmWriter *output) {
    cs_err err;
    err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &relocator->capstone);
    if (err) {
        Xerror("Failed on cs_open() with error returned: %u\n", err);
        exit(-1);
    }
    cs_option(relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);

    relocator->inpos = 0;
    relocator->outpos = 0;

    relocator->input_start = input_code;
    relocator->input_cur = input_code;
    relocator->input_pc = (zaddr)input_code;

    relocator->input_insns =
        (ZzInstruction *)malloc(MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(ZzInstruction));
    memset(relocator->input_insns, 0, MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(ZzInstruction));

    relocator->output = output;
}

void zz_arm_relocator_reset(ZzArmRelocator *self, zpointer input_code, ZzArmWriter *output) {
    self->input_cur = input_code;
    self->input_start = input_code;
    self->input_pc = (zaddr)input_code;

    self->inpos = 0;
    self->outpos = 0;

    self->output = output;
}

zsize zz_arm_relocator_read_one(ZzArmRelocator *self, ZzInstruction *instruction) {
    cs_insn **insn_cs_ptr, *insn_cs;
    ZzInstruction *insn_ctx = &self->input_insns[self->inpos];
    insn_cs_ptr = &insn_ctx->insn_cs;

    if (*insn_cs_ptr == NULL)
        *insn_cs_ptr = cs_malloc(self->capstone);

    // http://www.capstone-engine.org/iteration.html
    uint64_t address;
    size_t size;
    const uint8_t *code;

    code = self->input_cur;
    size = 4;
    address = self->input_pc;
    insn_cs = *insn_cs_ptr;

    if (!cs_disasm_iter(self->capstone, &code, &size, &address, insn_cs)) {
        return 0;
    }

    switch (insn_cs->id) {}

    self->inpos++;

    if (instruction != NULL)
        instruction = insn_ctx;

    self->input_cur += insn_cs->size;
    self->input_pc += insn_cs->size;

    return self->input_cur - self->input_start;
}
void zz_arm_relocator_try_relocate(zpointer address, zuint min_bytes, zuint *max_bytes) {
    *max_bytes = 16;
    return;
}

void zz_arm_relocator_write_all(ZzArmRelocator *self) {
    zuint count = 0;
    while (zz_arm_relocator_write_one(self))
        count++;
}

zbool zz_arm_relocator_write_one(ZzArmRelocator *self) {
    ZzInstruction *insn_ctx;
    cs_insn *insn_cs;
    zbool rewritten = FALSE;

    if (self->inpos != self->outpos) {
        insn_ctx = &self->input_insns[self->outpos];
        self->outpos++;
    } else
        return FALSE;

    insn_cs = insn_ctx->insn_cs;
    insn_ctx->pc = insn_cs->address + 8;
    insn_ctx->detail = &insn_cs->detail->arm;

    switch (insn_cs->id) {
    case ARM_INS_LDR:
        rewritten = zz_arm_relocator_rewrite_ldr(self, insn_ctx);
        break;
    case ARM_INS_ADD:
        rewritten = zz_arm_relocator_rewrite_add(self, insn_ctx);
        break;
    case ARM_INS_B:
        rewritten = zz_arm_relocator_rewrite_b(self, CS_MODE_ARM, insn_ctx);
        break;
    case ARM_INS_BX:
        rewritten = zz_arm_relocator_rewrite_b(self, CS_MODE_THUMB, insn_ctx);
        break;
    case ARM_INS_BL:
        rewritten = zz_arm_relocator_rewrite_bl(self, CS_MODE_ARM, insn_ctx);
        break;
    case ARM_INS_BLX:
        rewritten = zz_arm_relocator_rewrite_bl(self, CS_MODE_THUMB, insn_ctx);
        break;
    }
    if (!rewritten)
        zz_arm_writer_put_bytes(self->output, insn_cs->bytes, insn_cs->size);
    return TRUE;
}

static zbool zz_arm_branch_is_unconditional(const cs_insn *insn_ctx) {
    switch (insn_ctx->detail->arm.cc) {
    case ARM_CC_INVALID:
    case ARM_CC_AL:
        return TRUE;
    default:
        return FALSE;
    }
}

static zbool zz_arm_relocator_rewrite_ldr(ZzArmRelocator *self, ZzInstruction *insn_ctx) {
    const cs_arm_op *dst = &insn_ctx->detail->operands[0];
    const cs_arm_op *src = &insn_ctx->detail->operands[1];
    zint disp;

    if (src->type != ARM_OP_MEM || src->mem.base != ARM_REG_PC)
        return TRUE;

    disp = src->mem.disp;

    zz_arm_writer_put_ldr_b_reg_address(self->output, dst->reg, insn_ctx->pc);
    if (disp > 0xff) {
        zz_arm_writer_put_add_reg_reg_imm(self->output, dst->reg, dst->reg,
                                          0xc00 | ((disp >> 8) & 0xff));
    }
    zz_arm_writer_put_add_reg_reg_imm(self->output, dst->reg, dst->reg, disp & 0xff);
    zz_arm_writer_put_ldr_reg_reg_imm(self->output, dst->reg, dst->reg, 0);

    return TRUE;
}

static zbool zz_arm_relocator_rewrite_add(ZzArmRelocator *self, ZzInstruction *insn_ctx) {
    const cs_arm_op *dst = &insn_ctx->detail->operands[0];
    const cs_arm_op *left = &insn_ctx->detail->operands[1];
    const cs_arm_op *right = &insn_ctx->detail->operands[2];

    if (left->reg != ARM_REG_PC || right->type != ARM_OP_REG)
        return FALSE;

    if (right->reg == dst->reg) {
        zz_arm_writer_put_add_reg_reg_imm(self->output, dst->reg, dst->reg, insn_ctx->pc & 0xff);
        zz_arm_writer_put_add_reg_reg_imm(self->output, dst->reg, dst->reg,
                                          0xc00 | ((insn_ctx->pc >> 8) & 0xff));
        zz_arm_writer_put_add_reg_reg_imm(self->output, dst->reg, dst->reg,
                                          0x800 | ((insn_ctx->pc >> 16) & 0xff));
        zz_arm_writer_put_add_reg_reg_imm(self->output, dst->reg, dst->reg,
                                          0x400 | ((insn_ctx->pc >> 24) & 0xff));
    } else {
        zz_arm_writer_put_ldr_reg_address(self->output, dst->reg, insn_ctx->pc);
        zz_arm_writer_put_add_reg_reg_imm(self->output, dst->reg, right->reg, 0);
    }

    return TRUE;
}

static zbool zz_arm_relocator_rewrite_b(ZzArmRelocator *self, cs_mode target_mode,
                                        ZzInstruction *insn_ctx) {
    cs_insn *insn_cs = insn_ctx->insn_cs;
    const cs_arm_op *target = &insn_ctx->detail->operands[0];

    if (target->type != ARM_OP_IMM)
        return FALSE;

    zz_arm_writer_put_ldr_reg_address(
        self->output, ARM_REG_PC, (target_mode == CS_MODE_THUMB) ? target->imm | 1 : target->imm);
    return TRUE;
}

static zbool zz_arm_relocator_rewrite_bl(ZzArmRelocator *self, cs_mode target_mode,
                                         ZzInstruction *insn_ctx) {
    const cs_arm_op *target = &insn_ctx->detail->operands[0];

    if (target->type != ARM_OP_IMM)
        return FALSE;

    zz_arm_writer_put_ldr_reg_address(self->output, ARM_REG_LR, (zaddr)self->output->pc + (2 * 4));
    zz_arm_writer_put_ldr_reg_address(
        self->output, ARM_REG_PC, (target_mode == CS_MODE_THUMB) ? target->imm | 1 : target->imm);
    return TRUE;
}