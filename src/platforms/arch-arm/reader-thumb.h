#ifndef platforms_arch_thumb_reader_thumb_h
#define platforms_arch_thumb_reader_thumb_h

#include "hookzz.h"
#include "zkit.h"

#include "instructions.h"
#include "reader-arm.h"

typedef enum _ThumbInsnType {
  thumb_1_cbnz_cbz          = 0,
  thumb_1_comparebranch     = 0,
  thumb_1_b_T1              = 1,
  thumb_1_conditionalbranch = 1,
  thumb_ Thumb_INS_LDR_literal_T1,
  Thumb_INS_LDR_literal_T2,
  Thumb_INS_ADR_T1,
  Thumb_INS_ADR_T2,
  Thumb_INS_ADR_T3,
  Thumb_INS_B_T1,
  Thumb_INS_B_T2,
  Thumb_INS_B_T3,
  Thumb_INS_B_T4,
  Thumb_INS_BLBLX_immediate_T1,
  Thumb_INS_BLBLX_immediate_T2,
  Thumb_UNDEF
} ThumbInsnType;

// adr
// load literal
// conditional branch
// unconditional branch
// compare branch (cbz, cbnz)
// tbz, tbnz
void get_thumb_instruction_type(uint16_t inst) {

  uint32_t val, op, rm, rn, rd, shift, cond;
  int32_t offset;

  // adr
  if ((inst & 0xf800) == 0xa000) {
    rd            = get_insn_sub(inst, 8, 3);
    uint16_t imm8 = get_insn_sub(inst, 0, 8);
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
    uint16_t cond = get_insn_sub(inst, 8, 4);
    // cond != 111x
    if (cond >= 0b1110) {
      goto NOT_REWRITE_ROUTINE;
    }
    uint16_t imm8  = get_insn_sub(inst, 0, 8);
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
    uint16_t imm5  = get_insn_sub(inst, 3, 5);
    uint16_t i     = get_insn_sub(inst, 9, 1);
    uint32_t label = i << 6 | imm5 << 1;
    val            = instCTX->pc + label;

    rn = get_insn_sub(inst, 0, 3);

    if (self->output->pc % 4)
      thumb_assembly_writer_cclass(put_t1_nop)(self->output);

    imm5 = get_insn_sub(0x4 >> 1, 1, 5);
    i    = get_insn_sub(0x4 >> 1, 6, 1);
    thumb_assembly_writer_cclass(put_t1_instruction)(self->output, (inst & 0xfd07) | imm5 << 3 | i << 9);

    // conditional branch common rewrite
    thumb_assembly_writer_cclass(put_t1_nop)(self->output);
    thumb_assembly_writer_cclass(put_t2_b_imm)(self->output, 0x0);
    thumb_assembly_writer_cclass(put_load_reg_address)(self->output, arm_reg_index_pc, val);
  }

  // unconditional branch
  if ((inst & 0xf800) == 0xe000) {
    uint16_t imm11 = get_insn_sub(inst, 0, 11);
    uint32_t label = imm11 << 1;
    val            = instCTX->pc + label;

    if (self->output->pc % 4)
      thumb_assembly_writer_cclass(put_t1_nop)(self->output);

    thumb_assembly_writer_cclass(put_load_reg_address)(self->output, arm_reg_index_pc, val);
  }

  /* <<SAD: it's too hard to identify all instruction that use pc register>>
  // pc process with other register
  if ((inst & 0xfc00) == 0x4400) {
    uint16_t op = get_insn_sub(inst, 8, 2);
    // cond != 111x
    if (op == 0b11) {
      goto NOT_REWRITE_ROUTINE;
    }
    rd = get_insn_sub(inst, 7, 1) << 3 | get_insn_sub(inst, 0, 3);
    if (rd == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }
  */
}

// adr
// load literal
// conditional branch
// unconditional branch
// compare branch (cbz, cbnz)
// branch with link
// tbz, tbnz
void get_thumb2_instruction_type(uint16_t inst1, uint16_t inst2) {

  // conditional branch
  if ((inst1 & 0xf800) == 0xf000 && (inst2 & 0xd000) == 0x8000) {
    uint16_t cond = get_insn_sub(inst1, 6, 4);
    if (cond >= 0b1110) {
      rewrite_flag = 0;
      goto NOT_REWRITE_ROUTINE;
    }

    uint16_t S     = get_insn_sub(inst1, 10, 1);
    uint16_t J1    = get_insn_sub(inst2, 13, 1);
    uint16_t J2    = get_insn_sub(inst2, 11, 1);
    uint16_t imm6  = get_insn_sub(inst1, 0, 6);
    uint16_t imm11 = get_insn_sub(inst2, 0, 11);
  }

  // unconditional branch
  if ((inst1 & 0xf800) == 0xf000 && (inst2 & 0xd000) == 0x9000) {
    uint16_t S     = get_insn_sub(inst1, 10, 1);
    uint16_t J1    = get_insn_sub(inst2, 13, 1);
    uint16_t J2    = get_insn_sub(inst2, 11, 1);
    uint16_t imm10 = get_insn_sub(inst1, 0, 10);
    uint16_t imm11 = get_insn_sub(inst2, 0, 11);
  }

  // branch with link
  if ((inst1 & 0xf800) == 0xf000 && (inst2 & 0xd000) == 0xc000) {
    uint16_t S      = get_insn_sub(inst1, 10, 1);
    uint16_t J1     = get_insn_sub(inst2, 13, 1);
    uint16_t J2     = get_insn_sub(inst2, 11, 1);
    uint16_t imm10h = get_insn_sub(inst1, 0, 10);
    uint16_t imm10l = get_insn_sub(inst2, 1, 10);
  }

  /* <<SAD: it's too hard to identify all instruction that use pc register>>
  // data-processing (shifted register)
  if ((inst1 & 0xfe00) == 0xea00 && (inst2 & 0x8000) == 0) {
    uint16_t rn = get_insn_sub(inst1, 0, 4);
    uint16_t rd = get_insn_sub(inst2, 8, 4);
    uint16_t rm = get_insn_sub(inst2, 0, 4);
    if (rn == 15 || rd == 15 || rm == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }

  // data-processing (modified immediate)
  if ((inst1 & 0xfa00) == 0xf000 && (inst2 & 0x8000) == 0) {
    uint16_t rn = get_insn_sub(inst1, 0, 4);
    uint16_t rd = get_insn_sub(inst2, 8, 4);
    if (rn == 15 || rd == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }

  // load/store exclusive
  if ((inst1 & 0xffe0) == 0xe840) {
    uint16_t rn = get_insn_sub(inst1, 0, 4);
    uint16_t rd = get_insn_sub(inst2, 8, 4);
    uint16_t rt = get_insn_sub(inst2, 12, 4);
    if (rn == 15 || rd == 15 || rt == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }
  // Load/store exclusive byte/half/dual
  if ((inst1 & 0xffe0) == 0xe8c0 && (inst2 & 0x00c0) == 0x0040) {
    uint16_t rn  = get_insn_sub(inst1, 0, 4);
    uint16_t rd  = get_insn_sub(inst2, 0, 4);
    uint16_t rt  = get_insn_sub(inst2, 12, 4);
    uint16_t rt2 = get_insn_sub(inst2, 8, 4);
    if (rn == 15 || rd == 15 || rt == 15 || rt2 == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }

  // Load-acquire / Store-release
  if ((inst1 & 0xffe0) == 0xe8c0 && (inst2 & 0x0080) == 0x0080) {
    uint16_t rn  = get_insn_sub(inst1, 0, 4);
    uint16_t rd  = get_insn_sub(inst2, 0, 4);
    uint16_t rt  = get_insn_sub(inst2, 12, 4);
    uint16_t rt2 = get_insn_sub(inst2, 8, 4);
    if (rn == 15 || rd == 15 || rt == 15 || rt2 == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }

  // Load/store dual (immediate, post-indexed)
  if ((inst1 & 0xff60) == 0xe860) {
    uint16_t rn  = get_insn_sub(inst1, 0, 4);
    uint16_t rt  = get_insn_sub(inst2, 12, 4);
    uint16_t rt2 = get_insn_sub(inst2, 8, 4);
    if (rn == 15 || rt == 15 || rt2 == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }

  ...
  */
}

#endif