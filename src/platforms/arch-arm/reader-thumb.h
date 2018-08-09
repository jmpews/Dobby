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

void disass_thumb_insn(uint32_t insn) {
  uint32_t val, op, rm, rn, rd, shift, cond;
  int32_t offset;
  int i;
  switch (insn >> 12) {
  case 4:
    if (insn & (1 << 11)) {
      rd = (insn >> 8) & 7;
      /* load pc-relative.  Bit 1 of PC is ignored.  */
      val = s->pc + 2 + ((insn & 0xff) * 4);
      val &= ~(uint32_t)2;

      // up is qemu
      thumb_assembly_writer_cclass(put_load_reg_address)(self->output, rd, val);
      rewrite_flag = true;
      break;
    }
    if (insn & (1 << 10)) {
      /* 0b0100_01xx_xxxx_xxxx
             * - data processing extended, branch and exchange
             */
      rd = (insn & 7) | ((insn >> 4) & 8);
      rm = (insn >> 3) & 0xf;
      op = (insn >> 8) & 3;
      switch (op) {
      case 0: /* add */
        if (rd == 15 || rm == 15) {
          ERROR_NOT_IMPLICATION();
        }
        break;
      case 1: /* cmp */
        if (rd == 15 || rm == 15) {
          ERROR_NOT_IMPLICATION();
        }
        break;
      case 2: /* mov/cpy */
        if (rm == 15) {
          ERROR_NOT_IMPLICATION();
        }
        break;
      case 3: {
        // clear qemu code
      }
      }
      break;
    }
  }
}
#endif