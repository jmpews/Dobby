#include "writer-arm.h"

#include <stdlib.h>

// ATTENTION !!!:
// 写 writer 部分, 需要参考, `Instrcution Set Encoding` 部分
// `writer` REF: `ZzInstruction Set Encoding`

ZzARMAssemblerWriter *zz_arm_writer_new(zz_ptr_t data_ptr) {
    ZzARMAssemblerWriter *writer = (ZzARMAssemblerWriter *)zz_malloc_with_zero(sizeof(ZzARMAssemblerWriter));

    zz_addr_t align_address = (zz_addr_t)data_ptr & ~(zz_addr_t)3;
    writer->codedata        = (zz_ptr_t)align_address;
    writer->base            = (zz_ptr_t)align_address;
    writer->pc              = align_address;
    writer->size            = 0;

    writer->literal_insn_size = 0;
    memset(writer->literal_insns, 0, sizeof(ZzLiteralInstruction) * MAX_LITERAL_INSN_SIZE);

    return writer;
}

void zz_arm_writer_init(ZzARMAssemblerWriter *self, zz_ptr_t data_ptr) { zz_arm_writer_reset(self, data_ptr); }

void zz_arm_writer_reset(ZzARMAssemblerWriter *self, zz_ptr_t data_ptr) {

    zz_addr_t align_address = (zz_addr_t)data_ptr & ~(zz_addr_t)3;
    self->codedata          = (zz_ptr_t)align_address;
    self->base              = (zz_ptr_t)align_address;
    self->pc                = align_address;

    self->literal_insn_size = 0;
    memset(self->literal_insns, 0, sizeof(ZzLiteralInstruction) * MAX_LITERAL_INSN_SIZE);

    self->size = 0;
}

zz_size_t zz_arm_writer_near_jump_range_size() { return ((1 << 23) << 2); }

// ------- relocator -------

ZzLiteralInstruction *zz_arm_writer_put_ldr_b_reg_relocate_address(ZzARMAssemblerWriter *self, ZzARMReg reg,
                                                                   zz_addr_t address,
                                                                   ZzLiteralInstruction **literal_insn_ptr) {
    zz_arm_writer_put_ldr_b_reg_address(self, reg, address);
    ZzLiteralInstruction *literal_insn = &(self->literal_insns[self->literal_insn_size - 1]);
    *literal_insn_ptr                  = literal_insn;
    return literal_insn;
}

ZzLiteralInstruction *zz_arm_writer_put_ldr_reg_relocate_address(ZzARMAssemblerWriter *self, ZzARMReg reg,
                                                                 zz_addr_t address,
                                                                 ZzLiteralInstruction **literal_insn_ptr) {
    zz_arm_writer_put_ldr_reg_address(self, reg, address);
    ZzLiteralInstruction *literal_insn = &(self->literal_insns[self->literal_insn_size - 1]);
    *literal_insn_ptr                  = literal_insn;
    return literal_insn;
}

// ------- user custom -------

void zz_arm_writer_put_ldr_b_reg_address(ZzARMAssemblerWriter *self, ZzARMReg reg, zz_addr_t address) {
    self->literal_insns[self->literal_insn_size].literal_insn_ptr = self->codedata;
    zz_arm_writer_put_ldr_reg_reg_imm(self, reg, ZZ_ARM_REG_PC, 0);
    zz_arm_writer_put_b_imm(self, 0x0);
    self->literal_insns[self->literal_insn_size++].literal_address_ptr = self->codedata;
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
    memcpy(self->codedata, data, data_size);
    self->codedata = (zz_ptr_t)self->codedata + data_size;
    self->pc += data_size;
    self->size += data_size;
}

void zz_arm_writer_put_instruction(ZzARMAssemblerWriter *self, uint32_t insn) {
    *(uint32_t *)(self->codedata) = insn;
    self->codedata                = (zz_ptr_t)self->codedata + sizeof(uint32_t);
    self->pc += 4;
    self->size += 4;
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
    self->literal_insns[self->literal_insn_size].literal_insn_ptr = self->codedata;
    zz_arm_writer_put_ldr_reg_reg_imm(self, reg, ZZ_ARM_REG_PC, -4);
    self->literal_insns[self->literal_insn_size++].literal_address_ptr = self->codedata;
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