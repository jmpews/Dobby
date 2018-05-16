#include "writer-arm64.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

// REF:
// ARM Architecture Reference Manual ARMV8
// C2.1 Understanding the A64 instruction descriptions
// C2.1.3 The instruction encoding or encodings

ARM64AssemblyrWriter *arm64_writer_new(zz_ptr_t insns_buffer) {
    ARM64AssemblyrWriter *writer = (ARM64AssemblyrWriter *)malloc0(sizeof(ARM64AssemblyrWriter));
    writer->start_pc             = 0 + 4;
    writer->insns_buffer         = 0;
    writer->insnCTXs_count       = 0;
    writer->insns_size           = 0;
    return writer;
}

void arm64_writer_init(ARM64AssemblyrWriter *self, zz_addr_t insns_buffer, zz_addr_t targetPC) {
    arm64_writer_reset(self, insns_buffer, targetPC);
}

void arm64_writer_reset(ARM64AssemblyrWriter *self, zz_addr_t insns_buffer, zz_addr_t targetPC) {
    assert(insns_buffer % 4 == 0);
    assert(targetPC % 4 == 0);
    self->start_pc     = targetPC;
    self->insns_buffer = insns_buffer;
    self->insns_size   = 0;

    if (self->insnCTXs_count) {
        for (int i = 0; i < self->insnCTXs_count; ++i) {
            free(self->insnCTXs[i]);
        }
    }
    self->insnCTXs_count = 0;
}

void arm64_writer_free(ARM64AssemblyrWriter *self) {
    if (self->insnCTXs_count) {
        for (int i = 0; i < self->insnCTXs_count; i++) {
            free(self->insnCTXs[i]);
        }
    }
    free(self);
}

// ======= user custom =======

void arm64_writer_put_ldr_br_reg_address(ARM64AssemblyrWriter *self, ARM64Reg reg, zz_addr_t address) {
    arm64_writer_put_ldr_reg_imm(self, reg, 0x8);
    arm64_writer_put_br_reg(self, reg);
    arm64_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
}

void arm64_writer_put_ldr_blr_b_reg_address(ARM64AssemblyrWriter *self, ARM64Reg reg, zz_addr_t address) {
    arm64_writer_put_ldr_reg_imm(self, reg, 0xc);
    arm64_writer_put_blr_reg(self, reg);
    arm64_writer_put_b_imm(self, 0xc);
    arm64_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
}

void arm64_writer_put_ldr_b_reg_address(ARM64AssemblyrWriter *self, ARM64Reg reg, zz_addr_t address) {
    arm64_writer_put_ldr_reg_imm(self, reg, 0x8);
    arm64_writer_put_b_imm(self, 0xc);
    arm64_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(address));
}

zz_size_t arm64_writer_near_jump_range_size() { return ((1 << 25) << 2); }

void arm64_writer_put_ldr_br_b_reg_address(ARM64AssemblyrWriter *self, ARM64Reg reg, zz_addr_t address) {
    arm64_writer_put_ldr_reg_imm(self, reg, 0xc);
    arm64_writer_put_br_reg(self, reg);
    arm64_writer_put_b_imm(self, 0xc);
    arm64_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(address));
}

// ======= default =======

void arm64_writer_put_bytes(ARM64AssemblyrWriter *self, char *data, zz_size_t data_size) {
    zz_addr_t next_address = self->insns_buffer + self->insns_size;
    zz_addr_t next_pc      = self->start_pc + self->insns_size;
    memcpy((void *)next_address, data, data_size);
    self->insns_size += data_size;

    ARM64InstructionCTX *insn_ctx          = (ARM64InstructionCTX *)malloc0(sizeof(ARM64InstructionCTX));
    insn_ctx->pc                           = next_pc;
    insn_ctx->address                      = next_address;
    insn_ctx->size                         = data_size;
    insn_ctx->insn                         = 0;
    self->insnCTXs[self->insnCTXs_count++] = insn_ctx;
}

void arm64_writer_put_instruction(ARM64AssemblyrWriter *self, uint32_t insn) {
    zz_addr_t next_address = self->insns_buffer + self->insns_size;
    zz_addr_t next_pc      = self->start_pc + self->insns_size;
    memcpy((void *)next_address, &insn, sizeof(insn));

    self->insns_size += 4;

    ARM64InstructionCTX *insn_ctx          = (ARM64InstructionCTX *)malloc0(sizeof(ARM64InstructionCTX));
    insn_ctx->pc                           = next_pc;
    insn_ctx->address                      = next_address;
    insn_ctx->size                         = 4;
    insn_ctx->insn                         = insn;
    self->insnCTXs[self->insnCTXs_count++] = insn_ctx;
}

void arm64_writer_put_ldr_reg_imm(ARM64AssemblyrWriter *self, ARM64Reg reg, uint32_t offset) {
    ARM64RegInfo ri;
    arm64_register_describe(reg, &ri);

    uint32_t imm19, Rt_ndx;

    imm19  = offset >> 2;
    Rt_ndx = ri.index;

    arm64_writer_put_instruction(self, 0x58000000 | imm19 << 5 | Rt_ndx);
    return;
}

// PAGE: C6-871
void arm64_writer_put_str_reg_reg_offset(ARM64AssemblyrWriter *self, ARM64Reg src_reg, ARM64Reg dst_reg,
                                         uint64_t offset) {
    ARM64RegInfo rs, rd;

    arm64_register_describe(src_reg, &rs);
    arm64_register_describe(dst_reg, &rd);

    uint32_t size, v = 0, opc = 0, Rn_ndx, Rt_ndx;
    Rn_ndx = rd.index;
    Rt_ndx = rs.index;

    if (rs.is_integer) {
        size = (rs.width == 64) ? 0b11 : 0b10;
    }

    uint32_t imm12 = offset >> size;

    arm64_writer_put_instruction(self, 0x39000000 | size << 30 | opc << 22 | imm12 << 10 | Rn_ndx << 5 | Rt_ndx);
    return;
}

void arm64_writer_put_ldr_reg_reg_offset(ARM64AssemblyrWriter *self, ARM64Reg dst_reg, ARM64Reg src_reg,
                                         uint64_t offset) {
    ARM64RegInfo rs, rd;

    arm64_register_describe(src_reg, &rs);
    arm64_register_describe(dst_reg, &rd);

    uint32_t size, v = 0, opc = 0b01, Rn_ndx, Rt_ndx;
    Rn_ndx = rs.index;
    Rt_ndx = rd.index;

    if (rs.is_integer) {
        size = (rs.width == 64) ? 0b11 : 0b10;
    }

    uint32_t imm12 = offset >> size;

    arm64_writer_put_instruction(self, 0x39000000 | size << 30 | opc << 22 | imm12 << 10 | Rn_ndx << 5 | Rt_ndx);
    return;
}

// C6-562
void arm64_writer_put_br_reg(ARM64AssemblyrWriter *self, ARM64Reg reg) {
    ARM64RegInfo ri;
    arm64_register_describe(reg, &ri);

    uint32_t op = 0, Rn_ndx;
    Rn_ndx      = ri.index;
    arm64_writer_put_instruction(self, 0xd61f0000 | op << 21 | Rn_ndx << 5);
    return;
}

// C6-561
void arm64_writer_put_blr_reg(ARM64AssemblyrWriter *self, ARM64Reg reg) {
    ARM64RegInfo ri;
    arm64_register_describe(reg, &ri);

    uint32_t op = 0b01, Rn_ndx;

    Rn_ndx = ri.index;

    arm64_writer_put_instruction(self, 0xd63f0000 | op << 21 | Rn_ndx << 5);
    return;
}

// C6-550
void arm64_writer_put_b_imm(ARM64AssemblyrWriter *self, uint64_t offset) {
    uint32_t op = 0b0, imm26;
    imm26       = (offset >> 2) & 0x03ffffff;
    arm64_writer_put_instruction(self, 0x14000000 | op << 31 | imm26);
    return;
}

// TODO: standard form, need fix others
// PAGE: C6-549
void arm64_writer_put_b_cond_imm(ARM64AssemblyrWriter *self, uint32_t condition, uint64_t imm) {
    uint32_t imm19, cond;
    cond  = condition;
    imm19 = (imm >> 2) & 0x7ffff;
    arm64_writer_put_instruction(self, 0x54000000 | imm19 << 5 | cond);
    return;
}

// C6-525
void arm64_writer_put_add_reg_reg_imm(ARM64AssemblyrWriter *self, ARM64Reg dst_reg, ARM64Reg left_reg, uint64_t imm) {
    ARM64RegInfo rd, rl;

    arm64_register_describe(dst_reg, &rd);
    arm64_register_describe(left_reg, &rl);

    uint32_t sf = 1, op = 0, S = 0, shift = 0b00, imm12, Rn_ndx, Rd_ndx;

    Rd_ndx = rd.index;
    Rn_ndx = rl.index;
    imm12  = imm & 0xFFF;

    arm64_writer_put_instruction(self, 0x11000000 | sf << 31 | op << 30 | S << 29 | shift << 22 | imm12 << 10 |
                                           Rn_ndx << 5 | Rd_ndx);
    return;
}

// C6-930
void arm64_writer_put_sub_reg_reg_imm(ARM64AssemblyrWriter *self, ARM64Reg dst_reg, ARM64Reg left_reg, uint64_t imm) {
    ARM64RegInfo rd, rl;

    arm64_register_describe(dst_reg, &rd);
    arm64_register_describe(left_reg, &rl);

    uint32_t sf = 1, op = 1, S = 0, shift = 0b00, imm12, Rn_ndx, Rd_ndx;

    Rd_ndx = rd.index;
    Rn_ndx = rl.index;
    imm12  = imm & 0xFFF;

    arm64_writer_put_instruction(self, 0x11000000 | sf << 31 | op << 30 | S << 29 | shift << 22 | imm12 << 10 |
                                           Rn_ndx << 5 | Rd_ndx);
    return;
}