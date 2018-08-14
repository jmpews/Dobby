#ifndef platforms_arch_thumb_reader_thumb_h
#define platforms_arch_thumb_reader_thumb_h

#include "hookzz.h"
#include "zkit.h"

#include "arch-arm.h"
#include "instructions.h"
#include "reader-arm.h"

void get_thumb_instruction_type(uint16_t inst) {

  uint32_t val, op, rm, rn, rd, shift, cond;
  int32_t offset;

  // adr
  if ((inst & 0xf800) == 0xa000) {
    rd            = bits(inst, 8, 10);
    uint16_t imm8 = bits(inst, 0, 7);
    val           = instCTX->pc + imm8;

    if (self->output->pc % 4)
      thumb_assembly_writer_cclass(put_t1_nop)(self->output);

    // adr fix scheme
    thumb_assembly_writer_cclass(put_load_reg_address)(self->output, rd, val);
    rewrite_flag = true;
    return INST_THUMB_ADR;
  }

  // conditional branch fix scheme:
  // 0x4: b_cond 0x4
  // 0x6: nop
  // 0x8: b.w 0x0
  // 0xc: ldr.w pc, [pc, #label]
  if ((inst & 0xf000) == 0xd000) {
    uint16_t cond = bits(inst, 8, 11);
    // cond != 111x
    if (cond >= 0b1110) {
      goto NOT_REWRITE_ROUTINE;
    }
    uint16_t imm8  = bits(inst, 0, 7);
    uint32_t label = imm8 << 2;
    val            = instCTX->pc + label;

    // create label for b_cond
    // ThumbAssemblyLabel *label = thumb_assembly_writer_cclass(generate_new_label)(self->output);
    // thumb_assembly_writer_cclass(bind_label_with)(instCTX, 0, 8);
    // thumb_assembly_writer_cclass(put_label)(self->output, label);

    if (self->output->pc % 4)
      thumb_assembly_writer_cclass(put_t1_nop)(self->output);

    // modify imm8 field
    imm8 = 0x4 >> 2;
    thumb_assembly_writer_cclass(put_t1_instruction)(self->output, (inst & 0xfff0) | imm8);
    thumb_assembly_writer_cclass(put_t1_nop)(self->output);

    // conditional branch common rewrite
    thumb_assembly_writer_cclass(put_t2_b_imm)(self->output, 0x0);
    thumb_assembly_writer_cclass(put_load_reg_address)(self->output, arm_reg_index_pc, val);
  }

  // compare branch (cbz, cbnz)
  if ((inst & 0xf500) == 0xb100) {
    uint16_t imm5  = bits(inst, 3, 7);
    uint16_t i     = bit(inst, 9);
    uint32_t label = (i << 6) | (imm5 << 1);
    val            = instCTX->pc + label;

    rn = bits(inst, 0, 2);

    if (self->output->pc % 4)
      thumb_assembly_writer_cclass(put_t1_nop)(self->output);

    imm5 = bits(0x4 >> 1, 1, 5);
    i    = bit(0x4 >> 1, 6);
    thumb_assembly_writer_cclass(put_t1_instruction)(self->output, (inst & 0xfd07) | imm5 << 3 | i << 9);

    // conditional branch common rewrite
    thumb_assembly_writer_cclass(put_t1_nop)(self->output);
    thumb_assembly_writer_cclass(put_t2_b_imm)(self->output, 0x0);
    thumb_assembly_writer_cclass(put_load_reg_address)(self->output, arm_reg_index_pc, val);
  }

  // unconditional branch
  if ((inst & 0xf800) == 0xe000) {
    uint16_t imm11 = bits(inst, 0, 10);
    uint32_t label = imm11 << 1;
    val            = instCTX->pc + label;

    if (self->output->pc % 4)
      thumb_assembly_writer_cclass(put_t1_nop)(self->output);

    thumb_assembly_writer_cclass(put_load_reg_address)(self->output, arm_reg_index_pc, val);
  }
}

void get_thumb2_instruction_type(uint16_t inst1, uint16_t inst2) {

  // conditional branch
  // 0x4: b_cond 0x4
  // 0x8: b.w 0x0
  // 0xc: ldr.w pc, [pc, #label]
  if ((inst1 & 0xf800) == 0xf000 && (inst2 & 0xd000) == 0x8000) {
    uint16_t cond = bits(inst1, 6, 9);
    if (cond >= 0b1110) {
      rewrite_flag = 0;
      goto NOT_REWRITE_ROUTINE;
    }

    int S     = sbits(inst1, 10, 10);
    int J1    = bit(inst2, 13);
    int J2    = bit(inst2, 11);
    int imm6  = bits(inst1, 0, 5);
    int imm11 = bits(inst2, 0, 10);

    int32_t label = (imm11 << 1) | (imm6 << 12) | (J1 << 18) | (J2 << 19) | (S << 20);
    val           = instCTX->pc + label;

    // modify imm11 field
    imm11 = 0x4 >> 1;
    thumb_assembly_writer_cclass(put_t2_instruction)(self->output, inst1 & 0xfbff, (inst2 & 0xd800) | imm11);

    thumb_assembly_writer_cclass(put_t2_b_imm)(self->output, 0x0);
    thumb_assembly_writer_cclass(put_load_reg_address)(self->output, arm_reg_index_pc, val);
  }

  // unconditional branch
  if ((inst1 & 0xf800) == 0xf000 && (inst2 & 0xd000) == 0x9000) {
    int S     = sbits(inst1, 10, 10);
    int J1    = bit(inst2, 13);
    int J2    = bit(inst2, 11);
    int imm10 = bits(inst1, 0, 9);
    int imm11 = bits(inst2, 0, 10);
    int i1    = !(J1 ^ S);
    int i2    = !(J2 ^ S);

    int32_t label = (imm11 << 1) | (imm10 << 12) | (J1 << 22) | (J2 << 23) | (S << 24);
    val           = instCTX->pc + label;
    thumb_assembly_writer_cclass(put_load_reg_address)(self->output, arm_reg_index_pc, val);
  }

  // branch with link
  if ((inst1 & 0xf800) == 0xf000) {
    int S  = sbits(inst1, 10, 10);
    int J1 = bit(inst2, 13);
    int J2 = bit(inst2, 11);
    int i1 = !(J1 ^ S);
    int i2 = !(J2 ^ S);

    int op = bits(inst2, 12, 14);
    if ((op & 0b101) == 0b100) {
      // unconditional branch
      int imm10h    = bits(inst1, 0, 9);
      int imm10l    = bits(inst2, 1, 10);
      int32_t label = (imm10l << 2) | (imm10h << 12) | (i2 << 22) | (i1 << 23) | (S << 24);
      val           = instCTX->pc + label;
      thumb_assembly_writer_cclass(put_load_reg_address)(self->output, arm_reg_index_pc, val);
    } else {
      // conditional branch
      int imm11     = bits(inst2, 0, 10);
      int imm10     = bits(inst1, 0, 9);
      int32_t label = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (S << 24);
      val           = instCTX->pc + label;

      // modify imm11 field
      imm11 = 0x4 >> 1;
      thumb_assembly_writer_cclass(put_t2_instruction)(self->output, inst1 & 0xfbff, (inst2 & 0xd800) | imm11);

      thumb_assembly_writer_cclass(put_t2_b_imm)(self->output, 0x0);
      thumb_assembly_writer_cclass(put_load_reg_address)(self->output, arm_reg_index_pc, val);
    }
  }

  // adr
  if ((inst1 & 0xfb50) == 0xf200 & (inst2 & 0x8000) == 0) {
    int o1 = bit(inst1, 7);
    int o2 = bit(inst1, 5);
    int rn = bits(inst1, 0, 3);
    if (rn == 15 && o1 == 0 && o2 == 0) {
      // adr with add
      uint32_t i     = bit(inst1, 10);
      uint32_t imm3  = bits(inst2, 12, 14);
      uint32_t imm8  = bits(inst2, 0, 7);
      uint32_t label = imm8 | (imm3 << 8) | (i << 11);
      val            = instCTX->pc + label;
    } else if (rn == 15 && o1 == 1 && o2 == 1) {
      // adr with sub
      uint32_t i     = bit(inst1, 10);
      uint32_t imm3  = bits(inst2, 12, 14);
      uint32_t imm8  = bits(inst2, 0, 7);
      uint32_t label = imm8 | (imm3 << 8) | (i << 11);
      val            = instCTX->pc - label;
    }

    uint16_t rd = bits(inst2, 8, 11);
    thumb_assembly_writer_cclass(put_load_reg_address)(self->output, rd, val);
  }

  // load literal
  if ((inst1 & 0xff0f) == 0xf85f) {
    uint32_t U     = bit(inst1, 7);
    uint32_t imm12 = bits(inst2, 0, 11);
    uint16_t rt    = bits(inst2, 12, 15);

    uint32_t label = imm12;
    if (U == 1) {
      val = val + label;
    } else {
      val = val - label;
    }
    thumb_assembly_writer_cclass(put_load_reg_address)(self->output, rt, val);
    thumb_assembly_writer_cclass(put_t2_reg_reg_offset)(self->output, rt, rt, 0);
  }
}

#endif