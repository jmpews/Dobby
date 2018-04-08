#include "writer-arm.h"

#include <stdlib.h>

ARMAssemblerWriter *arm_writer_new() {
    ARMAssemblerWriter *writer = (ARMAssemblerWriter *)malloc0(sizeof(ARMAssemblerWriter));
    writer->current_address = 0;
    writer->start_address = 0;
    writer->current_pc = 0+8;
    writer->start_pc = 0+8;
    writer->size = 0;
    writer->insn_size = 0;
    return writer;
}

void arm_writer_init(ARMAssemblerWriter *self, zz_ptr_t data_ptr, zz_addr_t target_ptr) { arm_writer_reset(self, data_ptr, target_ptr); }

void arm_writer_reset(ARMAssemblerWriter *self, zz_ptr_t data_ptr, zz_addr_t target_ptr) {
    zz_addr_t align_address = (zz_addr_t)data_ptr & ~(zz_addr_t)3;
    self->current_address = align_address;
    self->start_address = align_address;
    self->current_pc = target_ptr+8;
    self->start_pc = target_ptr+8;
    self->size = 0;

    if(self->insn_size) {
        for (int i = 0; i < self->insn_size; ++i) {
            free(self->insns[i]);
        }
    }
    self->insn_size = 0;
}

void arm_writer_reset_without_align(ARMAssemblerWriter *self, zz_ptr_t data_ptr, zz_addr_t target_ptr) {
    zz_addr_t align_address = (zz_addr_t)data_ptr & ~(zz_addr_t)3;
    self->current_address = align_address;
    self->start_address = align_address;
    self->current_pc = target_ptr+8;
    self->start_pc = target_ptr+8;
    self->size = 0;

    if(self->insn_size) {
        for (int i = 0; i < self->insn_size; ++i) {
            free(self->insns[i]);
        }
    }
    self->insn_size = 0;
}

void arm_writer_free(ARMAssemblerWriter *self) {
    if (self->insn_size) {
        for (int i = 0; i < self->insn_size; i++) {
            free(self->insns[i]);
        }
    }
    free(self);
}
zz_size_t arm_writer_near_jump_range_size() { return ((1 << 23) << 2); }

// ------- user custom -------

void arm_writer_put_ldr_b_reg_address(ARMAssemblerWriter *self, ARMReg reg, zz_addr_t address) {
    arm_writer_put_ldr_reg_reg_imm(self, reg, ZZ_ARM_REG_PC, 0);
    arm_writer_put_b_imm(self, 0x0);
    arm_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
}

void arm_writer_put_bx_to_thumb(ARMAssemblerWriter *self) {
    arm_writer_put_sub_reg_reg_imm(self, ZZ_ARM_REG_SP, ZZ_ARM_REG_SP, 0x8);
    arm_writer_put_str_reg_reg_imm(self, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 0x0);
    arm_writer_put_add_reg_reg_imm(self, ZZ_ARM_REG_R1, ZZ_ARM_REG_PC, 9);
    arm_writer_put_str_reg_reg_imm(self, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 0x4);
    arm_writer_put_ldr_reg_reg_imm_index(self, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 4, 0);
    arm_writer_put_ldr_reg_reg_imm_index(self, ZZ_ARM_REG_PC, ZZ_ARM_REG_SP, 4, 0);
}
// ------- architecture default -------
void arm_writer_put_bytes(ARMAssemblerWriter *self, char *data, zz_size_t data_size) {
    memcpy((zz_ptr_t )self->current_address, data, data_size);
    self->current_address = self->current_address + data_size;
    self->current_pc += data_size;
    self->size += data_size;


    ARMInstruction *arm_insn = (ARMInstruction *)malloc0(sizeof(ARMInstruction));
    arm_insn->pc = self->current_pc - data_size;
    arm_insn->address = self->current_address-data_size;
    arm_insn->size = data_size;
    arm_insn->insn = 0;
    arm_insn->insn1 = 0;
    arm_insn->insn2 = 0;
    arm_insn->type = UNKOWN_INSN;
    self->insns[self->insn_size++] = arm_insn;
}

void arm_writer_put_instruction(ARMAssemblerWriter *self, uint32_t insn) {
    *(uint32_t *)(self->current_address) = insn;
    self->current_address                = self->current_address + sizeof(uint32_t);
    self->current_pc += 4;
    self->size += 4;

    ARMInstruction *arm_insn = (ARMInstruction *)malloc0(sizeof(ARMInstruction));
    arm_insn->pc = self->current_pc - 4;
    arm_insn->address = self->current_address-4;
    arm_insn->size = 4;
    arm_insn->insn = insn;
    arm_insn->insn1 = 0;
    arm_insn->insn2 = 0;
    arm_insn->type = ARM_INSN;
    self->insns[self->insn_size++] = arm_insn;
}

void arm_writer_put_b_imm(ARMAssemblerWriter *self, uint32_t imm) {
    arm_writer_put_instruction(self, 0xea000000 | ((imm / 4) & 0xffffff));
}

void arm_writer_put_ldr_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, int32_t imm) {
    ARMRegInfo rd, rs;

    arm_register_describe(dst_reg, &rd);
    arm_register_describe(src_reg, &rs);

    if (rs.meta == ZZ_ARM_REG_PC) {
        arm_writer_put_ldr_reg_imm_literal(self, dst_reg, imm);
    } else {
        bool P = 1;
        bool U = 0;
        bool W = 0;
        if (imm >= 0)
            U = 1;

        arm_writer_put_ldr_reg_reg_imm_A1(self, dst_reg, src_reg, ABS(imm), P, U, W);
    }
}

void arm_writer_put_ldr_reg_reg_imm_index(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg,
                                             int32_t imm, bool index) {
    ARMRegInfo rd, rs;

    arm_register_describe(dst_reg, &rd);
    arm_register_describe(src_reg, &rs);

    bool P = index;
    bool U = 0;
    bool W = 1;
    if (P == 0)
        W = 0;
    if (imm >= 0)
        U = 1;

    arm_writer_put_ldr_reg_reg_imm_A1(self, dst_reg, src_reg, ABS(imm), P, U, W);
}
void arm_writer_put_ldr_reg_reg_imm_A1(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, uint32_t imm,
                                          bool P, bool U, bool W) {
    ARMRegInfo rd, rs;

    arm_register_describe(dst_reg, &rd);
    arm_register_describe(src_reg, &rs);

    arm_writer_put_instruction(self, 0xe4100000 | rd.index << 12 | rs.index << 16 | P << 24 | U << 23 | W << 21 |
                                            (imm & ZZ_INT12_MASK));
}
void arm_writer_put_ldr_reg_imm_literal(ARMAssemblerWriter *self, ARMReg dst_reg, int32_t imm) {
    ARMRegInfo rd;

    arm_register_describe(dst_reg, &rd);
    bool U = 0;
    if (imm >= 0)
        U = 1;
    arm_writer_put_instruction(self, 0xe51f0000 | U << 23 | rd.index << 12 | (ABS(imm) & ZZ_INT12_MASK));
}

void arm_writer_put_str_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, int32_t imm) {
    ARMRegInfo rd, rs;

    arm_register_describe(dst_reg, &rd);
    arm_register_describe(src_reg, &rs);

    bool P = 1;
    bool U = 0;
    bool W = 0;
    if (imm >= 0)
        U = 1;
    arm_writer_put_instruction(self, 0xe4000000 | rd.index << 12 | rs.index << 16 | P << 24 | U << 23 | W << 21 |
                                            (imm & ZZ_INT12_MASK));
}

void arm_writer_put_ldr_reg_address(ARMAssemblerWriter *self, ARMReg reg, zz_addr_t address) {
    arm_writer_put_ldr_reg_reg_imm(self, reg, ZZ_ARM_REG_PC, -4);
    arm_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
}

void arm_writer_put_add_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, uint32_t imm) {
    ARMRegInfo rd, rs;

    arm_register_describe(dst_reg, &rd);
    arm_register_describe(src_reg, &rs);

    arm_writer_put_instruction(self, 0xe2800000 | rd.index << 12 | rs.index << 16 | (imm & ZZ_INT12_MASK));
}

void arm_writer_put_sub_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, uint32_t imm) {
    ARMRegInfo rd, rs;

    arm_register_describe(dst_reg, &rd);
    arm_register_describe(src_reg, &rs);

    arm_writer_put_instruction(self, 0xe2400000 | rd.index << 12 | rs.index << 16 | (imm & ZZ_INT12_MASK));
}

void arm_writer_put_bx_reg(ARMAssemblerWriter *self, ARMReg reg) {
    ARMRegInfo rs;
    arm_register_describe(reg, &rs);
    arm_writer_put_instruction(self, 0xe12fff10 | rs.index);
}

void arm_writer_put_nop(ARMAssemblerWriter *self) { arm_writer_put_instruction(self, 0xe320f000); }

void arm_writer_put_push_reg(ARMAssemblerWriter *self, ARMReg reg) {
    ARMRegInfo ri;
    arm_register_describe(reg, &ri);
    arm_writer_put_instruction(self, 0b11100101001011010000000000000100 | ri.index << 12);
    return;
}

void arm_writer_put_pop_reg(ARMAssemblerWriter *self, ARMReg reg) {
    ARMRegInfo ri;
    arm_register_describe(reg, &ri);

    arm_writer_put_instruction(self, 0b11100100100111010000000000000100 | ri.index << 12);
    return;
}