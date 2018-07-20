#include "writer-thumb.h"

#include <assert.h>
#include <stdlib.h>

ThumbAssemblerWriter *thumb_writer_new() {
  ThumbAssemblerWriter *writer = (ThumbAssemblerWriter *)malloc0(sizeof(ThumbAssemblerWriter));
  writer->start_pc             = 0 + 4;
  writer->insns_buffer         = 0;
  writer->insns_size           = 0;
  writer->insnCTXs_count       = 0;
  return writer;
}

void thumb_writer_init(ThumbAssemblerWriter *self, zz_addr_t insns_buffer, zz_addr_t targetPC) {
  thumb_writer_reset(self, insns_buffer, targetPC);
}

void thumb_writer_reset(ThumbAssemblerWriter *self, zz_addr_t insns_buffer, zz_addr_t targetPC) {
  assert(insns_buffer % 4 == 0);
  assert(targetPC % 4 == 0);
  self->start_pc     = targetPC + 4;
  self->insns_buffer = insns_buffer;
  self->insns_size   = 0;

  if (self->insnCTXs_count) {
    for (int i = 0; i < self->insnCTXs_count; ++i) {
      free(self->insnCTXs[i]);
      self->insnCTXs[i] = NULL;
    }
  }
  self->insnCTXs_count = 0;
}

void thumb_writer_free(ThumbAssemblerWriter *self) {
  if (self->insnCTXs_count) {
    for (int i = 0; i < self->insnCTXs_count; i++) {
      free(self->insnCTXs[i]);
      self->insnCTXs[i] = NULL;
    }
  }
  free(self);
}

zz_size_t thumb_writer_near_jump_range_size() {
  return ((1 << 23) << 1);
}

// ------- custom -------

void thumb_writer_put_ldr_b_reg_address(ThumbAssemblerWriter *self, ARMReg reg, zz_addr_t address) {
  ARMRegInfo ri;
  arm_register_describe(reg, &ri);

  zz_addr_t current_pc = self->start_pc + self->insns_size;

  if (current_pc % 4) {
    if (ri.meta <= ARM_REG_R7) {
      thumb_writer_put_ldr_reg_imm(self, reg, 0x4);
      thumb_writer_put_nop(self);
    } else {
      thumb_writer_put_ldr_reg_imm(self, reg, 0x4);
    }
  } else {
    if (ri.meta <= ARM_REG_R7) {
      thumb_writer_put_ldr_reg_imm(self, reg, 0x0);
    } else {
      thumb_writer_put_ldr_reg_imm(self, reg, 0x4);
      thumb_writer_put_nop(self);
    }
  }

  thumb_writer_put_b_imm(self, 0x2);
  thumb_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
  return;
}

void thumb_writer_put_ldr_reg_address(ThumbAssemblerWriter *self, ARMReg reg, zz_addr_t address) {
  ARMRegInfo ri;
  arm_register_describe(reg, &ri);

  zz_addr_t current_pc = self->start_pc + self->insns_size;

  if (current_pc % 4) {
    if (ri.meta <= ARM_REG_R7) {
      thumb_writer_put_ldr_reg_imm(self, reg, 0x0);
    } else {
      thumb_writer_put_ldr_reg_imm(self, reg, 0x4);
      thumb_writer_put_nop(self);
    }
  } else {
    thumb_writer_put_ldr_reg_imm(self, reg, 0x0);
    if (ri.meta <= ARM_REG_R7)
      thumb_writer_put_nop(self);
  }

  thumb_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
  return;
}

// ------- architecture default -------
void thumb_writer_put_nop(ThumbAssemblerWriter *self) {
  thumb_writer_put_instruction(self, 0x46c0);
  return;
}

void thumb_writer_put_bytes(ThumbAssemblerWriter *self, char *data, zz_size_t data_size) {
  zz_addr_t next_address = self->insns_buffer + self->insns_size;
  zz_addr_t next_pc      = self->start_pc + self->insns_size;
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
  return;
}

void thumb_writer_put_instruction(ThumbAssemblerWriter *self, uint16_t insn) {
  zz_addr_t next_address = self->insns_buffer + self->insns_size;
  zz_addr_t next_pc      = self->start_pc + self->insns_size;
  memcpy((void *)next_address, &insn, sizeof(insn));

  self->insns_size += 2;

  ARMInstruction *insn_ctx               = (ARMInstruction *)malloc0(sizeof(ARMInstruction));
  insn_ctx->pc                           = next_pc;
  insn_ctx->address                      = next_address;
  insn_ctx->size                         = 2;
  insn_ctx->insn                         = 0;
  insn_ctx->insn1                        = insn;
  insn_ctx->insn2                        = 0;
  insn_ctx->type                         = THUMB_INSN;
  self->insnCTXs[self->insnCTXs_count++] = insn_ctx;
  return;
}

void thumb_writer_put_b_imm(ThumbAssemblerWriter *self, uint32_t imm) {

  thumb_writer_put_instruction(self, 0xe000 | ((imm / 2) & ZZ_INT11_MASK));
  return;
}

void thumb_writer_put_bx_reg(ThumbAssemblerWriter *self, ARMReg reg) {
  ARMRegInfo ri;
  arm_register_describe(reg, &ri);

  zz_addr_t current_pc = self->start_pc + self->insns_size;

  if (current_pc % 4) {
    thumb_writer_put_nop(self);
  }

  thumb_writer_put_instruction(self, 0x4700 | (ri.index << 3));
  thumb_writer_put_nop(self);
  return;
}

void thumb_writer_put_blx_reg(ThumbAssemblerWriter *self, ARMReg reg) {
  ARMRegInfo ri;

  arm_register_describe(reg, &ri);

  thumb_writer_put_instruction(self, 0x4780 | (ri.index << 3));
  return;
}

// A8.8.18
void thumb_writer_put_branch_imm(ThumbAssemblerWriter *self, uint32_t imm, bool link, bool thumb) {
  union {
    int32_t i;
    uint32_t u;
  } distance;
  uint16_t s, j1, j2, imm10, imm11;

  distance.i = (int32_t)(imm) / 2;

  s  = (distance.u >> 31) & 1;
  j1 = (~((distance.u >> 22) ^ s)) & 1;
  j2 = (~((distance.u >> 21) ^ s)) & 1;

  imm10 = (distance.u >> 11) & ZZ_INT10_MASK;
  imm11 = distance.u & ZZ_INT11_MASK;

  thumb_writer_put_instruction(self, 0xf000 | (s << 10) | imm10);
  thumb_writer_put_instruction(self, 0x8000 | (link << 14) | (j1 << 13) | (thumb << 12) | (j2 << 11) | imm11);
  return;
}

void thumb_writer_put_bl_imm(ThumbAssemblerWriter *self, uint32_t imm) {
  thumb_writer_put_branch_imm(self, imm, TRUE, TRUE);
  return;
}

void thumb_writer_put_blx_imm(ThumbAssemblerWriter *self, uint32_t imm) {
  thumb_writer_put_branch_imm(self, imm, TRUE, FALSE);
  return;
}

void thumb_writer_put_b_imm32(ThumbAssemblerWriter *self, uint32_t imm) {
  thumb_writer_put_branch_imm(self, imm, FALSE, TRUE);
  return;
}

// PAGE: A8-410
// A8.8.64 LDR (literal)
void thumb_writer_put_ldr_reg_imm(ThumbAssemblerWriter *self, ARMReg reg, int32_t imm) {
  ARMRegInfo ri;

  arm_register_describe(reg, &ri);

  if (ri.meta <= ARM_REG_R7 && imm >= 0 && imm < ((1 << 8) << 2)) {

    thumb_writer_put_instruction(self, 0x4800 | (ri.index << 8) | ((imm / 4) & ZZ_INT8_MASK));
  } else if (imm < (1 << 12)) {
    bool add = 0;
    if (imm >= 0)
      add = 1;
    thumb_writer_put_instruction(self, 0xf85f | (add << 7));
    thumb_writer_put_instruction(self, (ri.index << 12) | ABS(imm));
  }
  return;
}

bool thumb_writer_put_transfer_reg_reg_offset_T1(ThumbAssemblerWriter *self, ThumbMemoryOperation operation,
                                                 ARMReg left_reg, ARMReg right_reg, int32_t right_offset) {
  ARMRegInfo lr, rr;

  arm_register_describe(left_reg, &lr);
  arm_register_describe(right_reg, &rr);

  uint16_t insn;

  if (right_offset < 0)
    return FALSE;

  if (lr.meta <= ARM_REG_R7 && rr.meta <= ARM_REG_R7 && right_offset < ((1 << 5) << 2)) {
    insn = 0x6000 | (right_offset / 4) << 6 | (rr.index << 3) | lr.index;
    if (operation == ZZ_THUMB_MEMORY_LOAD)
      insn |= 0x0800;
    thumb_writer_put_instruction(self, insn);
    return TRUE;
  }
  return FALSE;
}

bool thumb_writer_put_transfer_reg_reg_offset_T2(ThumbAssemblerWriter *self, ThumbMemoryOperation operation,
                                                 ARMReg left_reg, ARMReg right_reg, int32_t right_offset) {
  ARMRegInfo lr, rr;

  arm_register_describe(left_reg, &lr);
  arm_register_describe(right_reg, &rr);

  uint16_t insn;

  if (right_offset < 0)
    return FALSE;

  if (rr.meta == ARM_REG_SP && lr.meta <= ARM_REG_R7 && right_offset < ((1 << 8) << 2)) {
    insn = 0x9000 | (lr.index << 8) | (right_offset / 4);
    if (operation == ZZ_THUMB_MEMORY_LOAD)
      insn |= 0x0800;
    thumb_writer_put_instruction(self, insn);
    return TRUE;
  }
  return FALSE;
}

bool thumb_writer_put_transfer_reg_reg_offset_T3(ThumbAssemblerWriter *self, ThumbMemoryOperation operation,
                                                 ARMReg left_reg, ARMReg right_reg, int32_t right_offset) {
  ARMRegInfo lr, rr;

  arm_register_describe(left_reg, &lr);
  arm_register_describe(right_reg, &rr);

  uint16_t insn;

  if (right_offset < 0)
    return FALSE;

  if (right_offset < (1 << 12)) {
    if (rr.meta == ARM_REG_PC) {
      thumb_writer_put_ldr_reg_imm(self, left_reg, right_offset);
    }
    thumb_writer_put_instruction(self, 0xf8c0 | ((operation == ZZ_THUMB_MEMORY_LOAD) ? 0x0010 : 0x0000) | rr.index);
    thumb_writer_put_instruction(self, (lr.index << 12) | right_offset);

    return TRUE;
  }
  return FALSE;
}

bool thumb_writer_put_transfer_reg_reg_offset_T4(ThumbAssemblerWriter *self, ThumbMemoryOperation operation,
                                                 ARMReg left_reg, ARMReg right_reg, int32_t right_offset, bool index,
                                                 bool wback) {
  ARMRegInfo lr, rr;

  arm_register_describe(left_reg, &lr);
  arm_register_describe(right_reg, &rr);

  uint16_t insn;

  if (ABS(right_offset) < (1 << 8)) {
    if (rr.meta == ARM_REG_PC) {
      thumb_writer_put_ldr_reg_imm(self, left_reg, right_offset);
    } else {
      bool add = 0;
      if (right_offset > 0)
        add = 1;
      thumb_writer_put_instruction(self, 0xf840 | ((operation == ZZ_THUMB_MEMORY_LOAD) ? 0x0010 : 0x0000) | rr.index);
      thumb_writer_put_instruction(self, 0x0800 | (lr.index << 12) | (index << 10) | (add << 9) | (wback << 8) |
                                             (ABS(right_offset)));
      return TRUE;
    }
  }
  return FALSE;
}

// PAGE: A8-406
// PAGE: A8.8.203 STR (immediate, Thumb)
static void thumb_writer_put_transfer_reg_reg_offset(ThumbAssemblerWriter *self, ThumbMemoryOperation operation,
                                                     ARMReg left_reg, ARMReg right_reg, int32_t right_offset) {
  if (thumb_writer_put_transfer_reg_reg_offset_T1(self, operation, left_reg, right_reg, right_offset))
    return;

  if (thumb_writer_put_transfer_reg_reg_offset_T2(self, operation, left_reg, right_reg, right_offset))
    return;

  if (thumb_writer_put_transfer_reg_reg_offset_T3(self, operation, left_reg, right_reg, right_offset))
    return;
  if (thumb_writer_put_transfer_reg_reg_offset_T4(self, operation, left_reg, right_reg, right_offset, 1, 0))
    return;
  return;
}

void thumb_writer_put_ldr_reg_reg_offset(ThumbAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg,
                                         int32_t src_offset) {
  thumb_writer_put_transfer_reg_reg_offset(self, ZZ_THUMB_MEMORY_LOAD, dst_reg, src_reg, src_offset);
  return;
}

void thumb_writer_put_str_reg_reg_offset(ThumbAssemblerWriter *self, ARMReg src_reg, ARMReg dst_reg,
                                         int32_t dst_offset) {
  thumb_writer_put_transfer_reg_reg_offset(self, ZZ_THUMB_MEMORY_STORE, src_reg, dst_reg, dst_offset);
  return;
}

void thumb_writer_put_ldr_index_reg_reg_offset(ThumbAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg,
                                               int32_t src_offset, bool index) {
  thumb_writer_put_transfer_reg_reg_offset_T4(self, ZZ_THUMB_MEMORY_LOAD, dst_reg, src_reg, src_offset, index, 1);
  return;
}

void thumb_writer_put_str_index_reg_reg_offset(ThumbAssemblerWriter *self, ARMReg src_reg, ARMReg dst_reg,
                                               int32_t dst_offset, bool index) {
  thumb_writer_put_transfer_reg_reg_offset_T4(self, ZZ_THUMB_MEMORY_STORE, src_reg, dst_reg, dst_offset, index, 1);
  return;
}

void thumb_writer_put_str_reg_reg(ThumbAssemblerWriter *self, ARMReg src_reg, ARMReg dst_reg) {
  thumb_writer_put_str_reg_reg_offset(self, src_reg, dst_reg, 0);
  return;
}

void thumb_writer_put_ldr_reg_reg(ThumbAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg) {
  thumb_writer_put_ldr_reg_reg_offset(self, dst_reg, src_reg, 0);
  return;
}

void thumb_writer_put_add_reg_imm(ThumbAssemblerWriter *self, ARMReg dst_reg, int32_t imm) {
  ARMRegInfo dst;
  uint16_t sign_mask, insn;

  arm_register_describe(dst_reg, &dst);

  sign_mask = 0x0000;
  if (dst.meta == ARM_REG_SP) {

    if (imm < 0)
      sign_mask = 0x0080;

    insn = 0xb000 | sign_mask | ABS(imm / 4);
  } else {
    if (imm < 0)
      sign_mask = 0x0800;

    insn = 0x3000 | sign_mask | (dst.index << 8) | ABS(imm);
  }

  thumb_writer_put_instruction(self, insn);
  return;
}

void thumb_writer_put_sub_reg_imm(ThumbAssemblerWriter *self, ARMReg dst_reg, int32_t imm) {
  thumb_writer_put_add_reg_imm(self, dst_reg, -imm);
  return;
}

void thumb_writer_put_add_reg_reg_imm(ThumbAssemblerWriter *self, ARMReg dst_reg, ARMReg left_reg,
                                      int32_t right_value) {
  ARMRegInfo dst, left;
  uint16_t insn;

  arm_register_describe(dst_reg, &dst);
  arm_register_describe(left_reg, &left);

  if (left.meta == dst.meta) {
    return thumb_writer_put_add_reg_imm(self, dst_reg, right_value);
  }

  if (dst.meta <= ARM_REG_R7 && left.meta <= ARM_REG_R7 && ABS(right_value) < (1 << 3)) {
    uint32_t sign_mask = 0;

    if (right_value < 0)
      sign_mask = 1 << 9;

    insn = 0x1c00 | sign_mask | (ABS(right_value) << 6) | (left.index << 3) | dst.index;
    thumb_writer_put_instruction(self, insn);
  } else if ((left.meta == ARM_REG_SP || left.meta == ARM_REG_PC) && dst.meta <= ARM_REG_R7 && right_value > 0 &&
             (right_value % 4 == 0) && right_value < (1 << 8)) {
    uint16_t base_mask;

    if (left.meta == ARM_REG_SP)
      base_mask = 0x0800;
    else
      base_mask = 0x0000;

    insn = 0xa000 | base_mask | (dst.index << 8) | (right_value / 4);
    thumb_writer_put_instruction(self, insn);
  } else {
    uint16_t insn1, insn2;
    zz_size_t i, imm3, imm8;
    i    = (ABS(right_value) >> (3 + 8)) & 0x1;
    imm3 = (ABS(right_value) >> 8) & 0b111;
    imm8 = ABS(right_value) & 0b11111111;

    // A8-708, sub
    // A8-306 add
    if (right_value < 0)
      thumb_writer_put_instruction(self, 0b1111001010100000 | i << 10 | left.index);
    else
      thumb_writer_put_instruction(self, 0b1111001000000000 | i << 10 | left.index);
    thumb_writer_put_instruction(self, 0b0 | imm3 << 12 | dst.index << 8 | imm8);
  }

  return;
}

void thumb_writer_put_sub_reg_reg_imm(ThumbAssemblerWriter *self, ARMReg dst_reg, ARMReg left_reg,
                                      int32_t right_value) {
  thumb_writer_put_add_reg_reg_imm(self, dst_reg, left_reg, -right_value);
  return;
}

void thumb_writer_put_push_reg(ThumbAssemblerWriter *self, ARMReg reg) {
  ARMRegInfo ri;
  arm_register_describe(reg, &ri);

  uint16_t M, register_list;
  M = 0;

  thumb_writer_put_instruction(self, 0b1011010000000000 | M << 8 | 1 << ri.index);
  return;
}

void thumb_writer_put_pop_reg(ThumbAssemblerWriter *self, ARMReg reg) {
  ARMRegInfo ri;
  arm_register_describe(reg, &ri);

  uint16_t P, register_list;
  P = 0;

  thumb_writer_put_instruction(self, 0b1011110000000000 | P << 8 | 1 << ri.index);
  return;
}

void thumb_writer_put_add_reg_reg_reg(ThumbAssemblerWriter *self, ARMReg dst_reg, ARMReg left_reg, ARMReg right_reg) {
  ARMRegInfo dst, left, right;
  arm_register_describe(dst_reg, &dst);
  arm_register_describe(left_reg, &left);
  arm_register_describe(right_reg, &right);

  uint16_t Rm_ndx, Rn_ndx, Rd_ndx;
  Rd_ndx = dst.index;
  Rm_ndx = right.index;
  Rn_ndx = left.index;

  thumb_writer_put_instruction(self, 0b0001100000000000 | Rm_ndx << 6 | Rn_ndx << 3 | Rd_ndx);
  return;
}