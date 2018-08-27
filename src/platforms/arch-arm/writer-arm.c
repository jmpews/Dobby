#include "writer-arm.h"

#include <assert.h>
#include <stdlib.h>

ARMAssemblerWriter *arm_writer_new() {
  ARMAssemblerWriter *writer = (ARMAssemblerWriter *)malloc0(sizeof(ARMAssemblerWriter));
  writer->pc                 = 0 + 8;
  writer->insns_buffer       = 0;
  writer->insns_size         = 0;
  writer->insnCTXs_count     = 0;
  return writer;
}

void arm_writer_init(ARMAssemblerWriter *self, zz_addr_t insns_buffer, zz_addr_t targetPC) {
  arm_writer_reset(self, insns_buffer, targetPC);
}

void arm_writer_reset(ARMAssemblerWriter *self, zz_addr_t insns_buffer, zz_addr_t targetPC) {
  assert(insns_buffer % 4 == 0);
  assert(targetPC % 4 == 0);
  self->pc           = targetPC + 8;
  self->insns_buffer = insns_buffer;
  self->insns_size   = 0;

  if (self->insnCTXs_count) {
    for (int i = 0; i < self->insnCTXs_count; ++i) {
      free(self->insnCTXs[i]);
    }
  }
  self->insnCTXs_count = 0;
}

void arm_writer_reset_without_align(ARMAssemblerWriter *self, zz_addr_t insns_buffer, zz_addr_t targetPC) {
  self->pc           = targetPC + 8;
  self->insns_buffer = insns_buffer;
  self->insns_size   = 0;

  if (self->insnCTXs_count) {
    for (int i = 0; i < self->insnCTXs_count; ++i) {
      free(self->insnCTXs[i]);
    }
  }
  self->insnCTXs_count = 0;
}

void arm_writer_free(ARMAssemblerWriter *self) {
  if (self->insnCTXs_count) {
    for (int i = 0; i < self->insnCTXs_count; i++) {
      free(self->insnCTXs[i]);
    }
  }
  free(self);
}
zz_size_t arm_writer_near_jump_range_size() {
  return ((1 << 23) << 2);
}

// ------- user custom -------

void arm_writer_put_ldr_b_reg_address(ARMAssemblerWriter *self, ARMReg reg, zz_addr_t address) {
  arm_writer_put_ldr_reg_reg_imm(self, reg, ARM_REG_PC, 0);
  arm_writer_put_b_imm(self, 0x0);
  arm_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
}

void arm_writer_put_bx_to_thumb(ARMAssemblerWriter *self) {
  arm_writer_put_sub_reg_reg_imm(self, ARM_REG_SP, ARM_REG_SP, 0x8);
  arm_writer_put_str_reg_reg_imm(self, ARM_REG_R1, ARM_REG_SP, 0x0);
  arm_writer_put_add_reg_reg_imm(self, ARM_REG_R1, ARM_REG_PC, 9);
  arm_writer_put_str_reg_reg_imm(self, ARM_REG_R1, ARM_REG_SP, 0x4);
  arm_writer_put_ldr_reg_reg_imm_index(self, ARM_REG_R1, ARM_REG_SP, 4, 0);
  arm_writer_put_ldr_reg_reg_imm_index(self, ARM_REG_PC, ARM_REG_SP, 4, 0);
}
// ------- architecture default -------
void arm_writer_put_bytes(ARMAssemblerWriter *self, char *data, zz_size_t data_size) {
  zz_addr_t next_address = self->insns_buffer + self->insns_size;
  zz_addr_t next_pc      = self->pc + self->insns_size;
  memcpy((void *)next_address, data, data_size);
  self->insns_size += data_size;

  ARMInstruction *insn_ctx               = (ARMInstruction *)malloc0(sizeof(ARMInstruction));
  insn_ctx->pc                           = next_pc;
  insn_ctx->address                      = next_address;
  insn_ctx->size                         = data_size;
  insn_ctx->insn                         = 0;
  insn_ctx->insn1                        = 0;
  insn_ctx->insn2                        = 0;
  insn_ctx->type                         = UNKOWN_INSN;
  self->insnCTXs[self->insnCTXs_count++] = insn_ctx;
}

void arm_writer_put_instruction(ARMAssemblerWriter *self, uint32_t insn) {
  zz_addr_t next_address = self->insns_buffer + self->insns_size;
  zz_addr_t next_pc      = self->pc + self->insns_size;
  memcpy((void *)next_address, &insn, sizeof(insn));

  self->insns_size += 4;

  ARMInstruction *insn_ctx               = (ARMInstruction *)malloc0(sizeof(ARMInstruction));
  insn_ctx->pc                           = next_pc;
  insn_ctx->address                      = next_address;
  insn_ctx->size                         = 4;
  insn_ctx->insn                         = insn;
  insn_ctx->insn1                        = 0;
  insn_ctx->insn2                        = 0;
  insn_ctx->type                         = ARM_INSN;
  self->insnCTXs[self->insnCTXs_count++] = insn_ctx;
}

void arm_writer_put_b_imm(ARMAssemblerWriter *self, uint32_t imm) {
  arm_writer_put_instruction(self, 0xea000000 | ((imm / 4) & 0xffffff));
}

void arm_writer_put_ldr_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, int32_t imm) {
  ARMRegInfo rd, reg_ctx;

  arm_register_describe(dst_reg, &rd);
  arm_register_describe(src_reg, &reg_ctx);

  if (reg_ctx.meta == ARM_REG_PC) {
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

void arm_writer_put_ldr_reg_reg_imm_index(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, int32_t imm,
                                          bool index) {
  ARMRegInfo rd, reg_ctx;

  arm_register_describe(dst_reg, &rd);
  arm_register_describe(src_reg, &reg_ctx);

  bool P = index;
  bool U = 0;
  bool W = 1;
  if (P == 0)
    W = 0;
  if (imm >= 0)
    U = 1;

  arm_writer_put_ldr_reg_reg_imm_A1(self, dst_reg, src_reg, ABS(imm), P, U, W);
}
void arm_writer_put_ldr_reg_reg_imm_A1(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, uint32_t imm, bool P,
                                       bool U, bool W) {
  ARMRegInfo rd, reg_ctx;

  arm_register_describe(dst_reg, &rd);
  arm_register_describe(src_reg, &reg_ctx);

  arm_writer_put_instruction(self, 0xe4100000 | rd.index << 12 | reg_ctx.index << 16 | P << 24 | U << 23 | W << 21 |
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
  ARMRegInfo rd, reg_ctx;

  arm_register_describe(dst_reg, &rd);
  arm_register_describe(src_reg, &reg_ctx);

  bool P = 1;
  bool U = 0;
  bool W = 0;
  if (imm >= 0)
    U = 1;
  arm_writer_put_instruction(self, 0xe4000000 | rd.index << 12 | reg_ctx.index << 16 | P << 24 | U << 23 | W << 21 |
                                       (imm & ZZ_INT12_MASK));
}

void arm_writer_put_ldr_reg_address(ARMAssemblerWriter *self, ARMReg reg, zz_addr_t address) {
  arm_writer_put_ldr_reg_reg_imm(self, reg, ARM_REG_PC, -4);
  arm_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
}

void arm_writer_put_add_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, uint32_t imm) {
  ARMRegInfo rd, reg_ctx;

  arm_register_describe(dst_reg, &rd);
  arm_register_describe(src_reg, &reg_ctx);

  arm_writer_put_instruction(self, 0xe2800000 | rd.index << 12 | reg_ctx.index << 16 | (imm & ZZ_INT12_MASK));
}

void arm_writer_put_sub_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, uint32_t imm) {
  ARMRegInfo rd, reg_ctx;

  arm_register_describe(dst_reg, &rd);
  arm_register_describe(src_reg, &reg_ctx);

  arm_writer_put_instruction(self, 0xe2400000 | rd.index << 12 | reg_ctx.index << 16 | (imm & ZZ_INT12_MASK));
}

void arm_writer_put_bx_reg(ARMAssemblerWriter *self, ARMReg reg) {
  ARMRegInfo reg_ctx;
  arm_register_describe(reg, &reg_ctx);
  arm_writer_put_instruction(self, 0xe12fff10 | reg_ctx.index);
}

void arm_writer_put_nop(ARMAssemblerWriter *self) {
  arm_writer_put_instruction(self, 0xe320f000);
}

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