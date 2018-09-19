#include "srcxx/arch/arm/ARMInstructionRelocation.h"
#include "srcxx/globals.h"

#include "vm_core/arch/arm/registers-arm.h"
#include "vm_core/modules/assembler/assembler-arm.h"

namespace zz {
namespace arm {

typedef struct _PseudoLabelData {
  PseudoLabel label;
  uintptr_t address;
} PseudoLabelData;

static std::vector<PseudoLabelData> labels;

void ARMRelocateSingleInst(int32_t inst, uint32_t cur_pc, TurboAssembler &turbo_assembler) {
#define _ turbo_assembler.
  // top level encoding
  uint32_t cond, op0, op1;
  cond = bits(inst, 28, 31);
  op0  = bits(inst, 25, 27);
  op1  = bit(inst, 4);
  // Load/Store Word, Unsigned byte (immediate, literal)
  if (cond != 0b1111 && op0 == 0b010) {
    uint32_t P, U, o2, W, o1, Rn, Rt, imm12;
    P            = bit(inst, 24);
    W            = bit(inst, 21);
    imm12        = bits(inst, 0, 11);
    Rn           = bits(inst, 16, 19);
    Rt           = bits(inst, 12, 15);
    o1           = bit(inst, 20);
    o2           = bit(inst, 22);
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
      uint32_t target_address = imm12 + cur_pc;
      PseudoLabel PseudoDataLabel;
      Register regRt = Register::from_code(Rt);
      // =====
      _ Ldr(regRt, &PseudoDataLabel);
      _ ldr(regRt, MemOperand(regRt));
      // =====
      // Record the pseudo label to realized at the last.
      labels.push_back({PseudoDataLabel, target_address});
    } while (0);
  }

  // Data-processing and miscellaneous instructions
  if (cond != 0b1111 && (op0 & 0b110) == 0b000) {
    uint32_t op0, op1, op2, op3, op4;
    op0 = bit(inst, 25);
    // Data-processing immediate
    if (op0 == 1) {
      uint32_t op0, op1;
      op0 = bits(inst, 23, 24);
      op1 = bits(inst, 20, 21);
      // Integer Data Processing (two register and immediate)
      if ((op0 & 0b10) == 0b00) {
        uint32_t opc, S, Rn;
        opc = bits(inst, 21, 23);
        S   = bit(inst, 20);
        Rn  = bits(inst, 16, 19);
        do {
          uint32_t target_address;
          int Rd    = bits(inst, 12, 15);
          int imm12 = bits(inst, 0, 11);
          int label = imm12;
          if (opc == 0b010 && S == 0b0 && Rn == 0b1111) {
            // ADR - A2 variant
            // add = FALSE
            target_address = cur_pc - imm12;
          } else if (opc == 0b100 && S == 0b0 && Rn == 0b1111) {
            // ADR - A1 variant
            // add = TRUE
            target_address = cur_pc + imm12;
          } else
            break;

          PseudoLabel PseudoDataLabel;
          Register regRd = Register::from_code(Rd);
          // =====
          _ Ldr(regRd, &PseudoDataLabel);
          // =====
          // Record the pseudo label to realized at the last.
          labels.push_back({PseudoDataLabel, target_address});
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
        int imm24               = bits(inst, 0, 23);
        int label               = imm24 << 2;
        uint32_t target_address = cur_pc + label;
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

        // =====
        // just modify oriign instruction label bits, and keep the link and cond bits, the next instruction `b_imm` will do the rest work.
        label = 0x4;
        imm24 = label >> 2;
        _ Emit((inst & 0xff000000) | imm24);
        if (flag_link) {
          _ bl(0);
          _ b(4);
        } else {
          _ b(0);
        }
        _ ldr(pc, MemOperand(pc, -4));
        _ Emit(target_address);
      } while (0);
    }
  }

  if (cond == 0b1111 && (op0 & 0b100) == 0b000) {
  }
}

// =====

void Thumb1RelocateSingleInst(int16_t inst, uint32_t cur_pc, TurboAssembler &turbo_assembler) {

  uint32_t val, op, rm, rn, rd, shift, cond;
  int32_t offset;

  // adr
  if ((inst & 0xf800) == 0xa000) {
    rd            = bits(inst, 8, 10);
    uint16_t imm8 = bits(inst, 0, 7);
    val           = cur_pc + imm8;

    if (cur_pc % 4)
      _ t1_nop();

    PseudoLabel PseudoDataLabel;
    // =====
    _ T1_Ldr(Register::from_code(rd), &PseudoDataLabel);
    // =====
    labels.push_back({PseudoDataLabel, val}) rewrite_flag = true;
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
      UNREACHABLE();
    }
    uint16_t imm8  = bits(inst, 0, 7);
    uint32_t label = imm8 << 2;
    val            = cur_pc + label;

    if (cur_pc % 4)
      _ t1_nop();

    PseudoLabel PseudoDataLabel;
    // modify imm8 field
    imm8 = 0x4 >> 2;
    // =====
    _ EmitInt16((inst & 0xfff0) | imm8);
    _ t1_nop();
    _ t1_b(0);
    _ T1_Ldr(pc, &PseudoDataLabel);
    // =====
    labels.push_back({PseudoDataLabel, val});
  }

  // compare branch (cbz, cbnz)
  if ((inst & 0xf500) == 0xb100) {
    uint16_t imm5  = bits(inst, 3, 7);
    uint16_t i     = bit(inst, 9);
    uint32_t label = (i << 6) | (imm5 << 1);
    val            = cur_pc + label;

    rn = bits(inst, 0, 2);

    if (cur_pc % 4)
      _ t1_nop();

    PseudoLabel PseudoDataLabel;
    // =====
    imm5 = bits(0x4 >> 1, 1, 5);
    i    = bit(0x4 >> 1, 6);
    _ EmitInt16((inst & 0xfd07) | imm5 << 3 | i << 9);
    _ t1_nop();
    _ t2_b(0);
    _ T1_Ldr(pc, &PseudoDataLabel);
  }

  // unconditional branch
  if ((inst & 0xf800) == 0xe000) {
    uint16_t imm11 = bits(inst, 0, 10);
    uint32_t label = imm11 << 1;
    val            = cur_pc + label;

    if (self->output->pc % 4)
      _ t1_nop();

    PseudoLabel PseudoDataLabel;
    // =====
    _ T1_Ldr(pc, &PseudoDataLabel);
    // =====
  }
}

void Thumb2RelocateSingleInst(int32_t inst, uint32_t cur_pc, TurboAssembler &turbo_assembler) {
}

void ThumbRelocateSingleInst(int32_t inst, uint32_t cur_pc, TurboAssembler &turbo_assembler) {
}

// =====

Code *GenRelocateCode(uintptr_t src_pc, int count) {
  uintptr_t cur_pc = src_pc;
  uint32_t inst    = *(uint32_t *)src_pc;
  int t            = 0;
  TurboAssembler turbo_assembler_;
#define _ turbo_assembler_.
  while (t < count) {
    ARMRelocateSingleInst(inst, cur_pc, turbo_assembler_);

    // Move to next instruction
    cur_pc += 4;
    t++;
    inst = *(uint32_t *)cur_pc;
  }

  // Generate executable code
  AssemblerCode *code = AssemblerCode::FinalizeTurboAssembler(&turbo_assembler_);
  return code;
}

} // namespace arm
} // namespace zz
