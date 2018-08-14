#ifndef platforms_arch_arm_reader_arm_h
#define platforms_arch_arm_reader_arm_h

#include "core.h"
#include "instruction.h"

#include "std_kit/std_kit.h"

typedef struct _ARMAssemblyReader {
  void *pc;
  void *buffer;
  list_t *instCTXs;
  buffer_array_t *inst_bytes;
} ARMAssemblyReader;

#define arm_assembly_reader_cclass(member) cclass(arm_assembly_reader, member)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus
ARMAssemblyReader *arm_assembly_reader_cclass(new)(void *address, void *pc);

void arm_assembly_reader_cclass(reset)(ARMAssemblyReader *self, void *address, void *pc);

ARMInstructionCTX *arm_assembly_reader_cclass(read_inst)(ARMAssemblyReader *self);
#ifdef __cplusplus
}
#endif //__cplusplus

void fix_arm_instruction(uint32_t inst) {
  // top level encoding
  uint32_t cond, op0, op1;
  cond = bits(inst, 28, 31);
  op0  = bits(inst, 25, 27);
  op1  = bit(inst, 4);
  // Load/Store Word, Unsigned byte (immediate, literal)
  if (cond != 0b1111 && op0 == 0b010) {
    uint32_t P, U, o2, W, o1, Rn, Rt, imm12;
    uint32_t P_W = (P << 1) | W;
    do {
      // LDR (literal)
      if (o1 == 1 && o2 == 0 && P_W != 0b01 && Rn == 0b1111) {
        goto load_literal_fix_scheme;
      }
      if (o1 == 1 && o2 == 1 && P_W != 0b01 && Rn == 0b1111) {
        goto load_literal_fix_scheme;
      }

      break;
    load_literal_fix_scheme:
      uint32_t Rt = bits(inst, 12, 15);
      thumb_assembly_writer_cclass(put_load_reg_address)(self->output, rt, val);
      thumb_assembly_writer_cclass(put_reg_reg_offset)(self->output, rt, rt, 0);
    } while (0);
  }

  // Data-processing and miscellaneous instructions
  if (cond != 0b1111 && (op0 & 0b110) == 0b000) {
    uint32_t op0, op1, op2, op3, op4;
    op0 = bit(inst, 25);
    // Data-processing immediate
    if (op0 == 1) {
      uint32_t op0, op1;
      op0 == bits(inst, 23, 24);
      op1 == bits(inst, 20, 21);
      // Integer Data Processing (two register and immediate)
      if ((op0 & 0b10) == 0b00) {
        uint32_t opc, S, Rn;
        opc = bits(inst, 21, 23);
        S   = bit(inst, 20);
        Rn  = bits(inst, 16, 19);
        do {
          int Rd    = bits(inst, 12, 15);
          int imm12 = bits(inst, 0, 11);
          int label = imm12;
          if (opc == 0b010 && S == 0b0 && Rn == 0b1111) {
            // ADR - A2 variant
            // add = FALSE
            val = instCTX->pc - imm12;
          } else if (opc == 0b100 && S == 0b0 && Rn == 0b1111) {
            // ADR - A1 variant
            // add = TRUE
            val = instCTX->pc + imm12;
          } else
            break;

          arm_assembly_writer_cclass(put_load_reg_address)(self->output, Rd, val);
        } while (0);
        // EXample
        if (opc == 0b111 && S == 0b1 && Rn == 0b1111) {
          // do something
        }
      }
    }
  }

  // Branch, branch with link, and block data transfer
  if (cond && (op0 & 0b110) == 0b100) {
    uint32_t cond, op0;
    cond = bits(inst, 28, 31);
    op0  = bit(inst, 25);
    // Branch (immediate)
    if (op0 == 1) {
      uint32_t cond, H, imm24;
      bool flag_link;
      do {
        int imm24 = bits(inst, 0, 23);
        int label = imm24 << 2;
        val       = instCTX->pc + label;
        if (cond != 0b1111 && H == 0) {
          // B
          flag_link = false;
        } else if (cond != 0b1111 && H == 1) {
          // BL, BLX (immediate) - A1 variant
          flag_link = true;
        } else if (cond == 0b1111) {
          // BL, BLX (immediate) - A2 variant
          flag_link = true;
        } else
          break;

        label = 0x4;
        imm24 = label >> 2;
        // just modify oriign instruction label bits, and keep the link and cond bits, the next instruction `b_imm` will do the rest work.
        arm_assembly_writer_cclass(put_instruction)(self->output, (inst & 0xff000000) | imm24);
        arm_assembly_writer_cclass(put_b_imm)(self->output, 0);
        arm_assembly_writer_cclass(put_load_reg_address)(self->output, arm_reg_index_pc, val);
      } while (0);
    }
  }

  if (cond == 0b1111 && (op0 & 0b100) == 0b000) {
  }
}

#endif