#include "writer-arm.h"

#include <stdlib.h>

ZzARMAssemblerWriter *zz_arm_writer_new() {
    ZzARMAssemblerWriter *writer = (ZzARMAssemblerWriter *)zz_malloc_with_zero(sizeof(ZzARMAssemblerWriter));
    writer->w_current_address = 0;
    writer->w_start_address = 0;
    writer->current_pc = 0+8;
    writer->start_pc = 0+8;
    writer->size = 0;
    writer->insn_size = 0;
    return writer;
}

void zz_arm_writer_init(ZzARMAssemblerWriter *self, zz_ptr_t data_ptr, zz_addr_t target_ptr) { zz_arm_writer_reset(self, data_ptr, target_ptr); }

void zz_arm_writer_reset(ZzARMAssemblerWriter *self, zz_ptr_t data_ptr, zz_addr_t target_ptr) {
    zz_addr_t align_address = (zz_addr_t)data_ptr & ~(zz_addr_t)3;
    self->w_current_address = align_address;
    self->w_start_address = align_address;
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

void zz_arm_writer_reset_without_align(ZzARMAssemblerWriter *self, zz_ptr_t data_ptr, zz_addr_t target_ptr) {
    zz_addr_t align_address = (zz_addr_t)data_ptr & ~(zz_addr_t)3;
    self->w_current_address = align_address;
    self->w_start_address = align_address;
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

void zz_arm_writer_free(ZzARMAssemblerWriter *self) {
    if (self->insn_size) {
        for (int i = 0; i < self->insn_size; i++) {
            free(self->insns[i]);
        }
    }
    free(self);
}
zz_size_t zz_arm_writer_near_jump_range_size() { return ((1 << 23) << 2); }

// ------- user custom -------

void zz_arm_writer_put_ldr_b_reg_address(ZzARMAssemblerWriter *self, ZzARMReg reg, zz_addr_t address) {
    zz_arm_writer_put_ldr_reg_reg_imm(self, reg, ZZ_ARM_REG_PC, 0);
    zz_arm_writer_put_b_imm(self, 0x0);
    zz_arm_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
}

void zz_arm_writer_put_bx_to_thumb(ZzARMAssemblerWriter *self) {
    zz_arm_writer_put_sub_reg_reg_imm(self, ZZ_ARM_REG_SP, ZZ_ARM_REG_SP, 0x8);
    zz_arm_writer_put_str_reg_reg_imm(self, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 0x0);
    zz_arm_writer_put_add_reg_reg_imm(self, ZZ_ARM_REG_R1, ZZ_ARM_REG_PC, 9);
    zz_arm_writer_put_str_reg_reg_imm(self, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 0x4);
    zz_arm_writer_put_ldr_reg_reg_imm_index(self, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 4, 0);
    zz_arm_writer_put_ldr_reg_reg_imm_index(self, ZZ_ARM_REG_PC, ZZ_ARM_REG_SP, 4, 0);
}
// ------- architecture default -------
void zz_arm_writer_put_bytes(ZzARMAssemblerWriter *self, char *data, zz_size_t data_size) {
    memcpy((zz_ptr_t )self->w_current_address, data, data_size);
    self->w_current_address = self->w_current_address + data_size;
    self->current_pc += data_size;
    self->size += data_size;


    ZzARMInstruction *arm_insn = (ZzARMInstruction *)zz_malloc_with_zero(sizeof(ZzARMInstruction));
    arm_insn->pc = self->current_pc - data_size;
    arm_insn->address = self->w_current_address-data_size;
    arm_insn->size = data_size;
    arm_insn->insn = 0;
    arm_insn->insn1 = 0;
    arm_insn->insn2 = 0;
    arm_insn->type = UNKOWN_INSN;
    self->insns[self->insn_size++] = arm_insn;
}

void zz_arm_writer_put_instruction(ZzARMAssemblerWriter *self, uint32_t insn) {
    *(uint32_t *)(self->w_current_address) = insn;
    self->w_current_address                = self->w_current_address + sizeof(uint32_t);
    self->current_pc += 4;
    self->size += 4;

    ZzARMInstruction *arm_insn = (ZzARMInstruction *)zz_malloc_with_zero(sizeof(ZzARMInstruction));
    arm_insn->pc = self->current_pc - 4;
    arm_insn->address = self->w_current_address-4;
    arm_insn->size = 4;
    arm_insn->insn = insn;
    arm_insn->insn1 = 0;
    arm_insn->insn2 = 0;
    arm_insn->type = ARM_INSN;
    self->insns[self->insn_size++] = arm_insn;
}

void zz_arm_writer_put_b_imm(ZzARMAssemblerWriter *self, uint32_t imm) {
    zz_arm_writer_put_instruction(self, 0xea000000 | ((imm / 4) & 0xffffff));
}

void zz_arm_writer_put_ldr_reg_reg_imm(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, int32_t imm) {
    ZzARMRegInfo rd, rs;

    zz_arm_register_describe(dst_reg, &rd);
    zz_arm_register_describe(src_reg, &rs);

    if (rs.meta == ZZ_ARM_REG_PC) {
        zz_arm_writer_put_ldr_reg_imm_literal(self, dst_reg, imm);
    } else {
        bool P = 1;
        bool U = 0;
        bool W = 0;
        if (imm >= 0)
            U = 1;

        zz_arm_writer_put_ldr_reg_reg_imm_A1(self, dst_reg, src_reg, ABS(imm), P, U, W);
    }
}

void zz_arm_writer_put_ldr_reg_reg_imm_index(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg,
                                             int32_t imm, bool index) {
    ZzARMRegInfo rd, rs;

    zz_arm_register_describe(dst_reg, &rd);
    zz_arm_register_describe(src_reg, &rs);

    bool P = index;
    bool U = 0;
    bool W = 1;
    if (P == 0)
        W = 0;
    if (imm >= 0)
        U = 1;

    zz_arm_writer_put_ldr_reg_reg_imm_A1(self, dst_reg, src_reg, ABS(imm), P, U, W);
}
void zz_arm_writer_put_ldr_reg_reg_imm_A1(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, uint32_t imm,
                                          bool P, bool U, bool W) {
    ZzARMRegInfo rd, rs;

    zz_arm_register_describe(dst_reg, &rd);
    zz_arm_register_describe(src_reg, &rs);

    zz_arm_writer_put_instruction(self, 0xe4100000 | rd.index << 12 | rs.index << 16 | P << 24 | U << 23 | W << 21 |
                                            (imm & ZZ_INT12_MASK));
}
void zz_arm_writer_put_ldr_reg_imm_literal(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, int32_t imm) {
    ZzARMRegInfo rd;

    zz_arm_register_describe(dst_reg, &rd);
    bool U = 0;
    if (imm >= 0)
        U = 1;
    zz_arm_writer_put_instruction(self, 0xe51f0000 | U << 23 | rd.index << 12 | (ABS(imm) & ZZ_INT12_MASK));
}

void zz_arm_writer_put_str_reg_reg_imm(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, int32_t imm) {
    ZzARMRegInfo rd, rs;

    zz_arm_register_describe(dst_reg, &rd);
    zz_arm_register_describe(src_reg, &rs);

    bool P = 1;
    bool U = 0;
    bool W = 0;
    if (imm >= 0)
        U = 1;
    zz_arm_writer_put_instruction(self, 0xe4000000 | rd.index << 12 | rs.index << 16 | P << 24 | U << 23 | W << 21 |
                                            (imm & ZZ_INT12_MASK));
}

void zz_arm_writer_put_ldr_reg_address(ZzARMAssemblerWriter *self, ZzARMReg reg, zz_addr_t address) {
    zz_arm_writer_put_ldr_reg_reg_imm(self, reg, ZZ_ARM_REG_PC, -4);
    zz_arm_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
}

void zz_arm_writer_put_add_reg_reg_imm(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, uint32_t imm) {
    ZzARMRegInfo rd, rs;

    zz_arm_register_describe(dst_reg, &rd);
    zz_arm_register_describe(src_reg, &rs);

    zz_arm_writer_put_instruction(self, 0xe2800000 | rd.index << 12 | rs.index << 16 | (imm & ZZ_INT12_MASK));
}

void zz_arm_writer_put_sub_reg_reg_imm(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, uint32_t imm) {
    ZzARMRegInfo rd, rs;

    zz_arm_register_describe(dst_reg, &rd);
    zz_arm_register_describe(src_reg, &rs);

    zz_arm_writer_put_instruction(self, 0xe2400000 | rd.index << 12 | rs.index << 16 | (imm & ZZ_INT12_MASK));
}

void zz_arm_writer_put_bx_reg(ZzARMAssemblerWriter *self, ZzARMReg reg) {
    ZzARMRegInfo rs;
    zz_arm_register_describe(reg, &rs);
    zz_arm_writer_put_instruction(self, 0xe12fff10 | rs.index);
}

void zz_arm_writer_put_nop(ZzARMAssemblerWriter *self) { zz_arm_writer_put_instruction(self, 0xe320f000); }

void zz_arm_writer_put_push_reg(ZzARMAssemblerWriter *self, ZzARMReg reg) {
    ZzARMRegInfo ri;
    zz_arm_register_describe(reg, &ri);
    zz_arm_writer_put_instruction(self, 0b11100101001011010000000000000100 | ri.index << 12);
    return;
}

void zz_arm_writer_put_pop_reg(ZzARMAssemblerWriter *self, ZzARMReg reg) {
    ZzARMRegInfo ri;
    zz_arm_register_describe(reg, &ri);

    zz_arm_writer_put_instruction(self, 0b11100100100111010000000000000100 | ri.index << 12);
    return;
}