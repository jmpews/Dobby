#include "arch/arm/ARMInstructionRelocation.h"
#include "arch/arm/ARMInterceptRouting.h"
#include "globals.h"

#include "vm_core/arch/arm/registers-arm.h"
#include "vm_core/modules/assembler/assembler-arm.h"
#include "vm_core/modules/codegen/codegen-arm.h"

namespace zz {
namespace arm {

static bool is_thumb2(uint32_t inst) {
  uint16_t inst1, inst2;
  inst1        = inst & 0x0000ffff;
  inst2        = (inst & 0xffff0000) >> 16;
  uint32_t op0 = bits(inst1, 11, 12);

  if (op0 == 0b111) {
    return true;
  }
  return false;
}

typedef struct _PseudoLabelData {
  PseudoLabel label;
  uintptr_t address;
} PseudoLabelData;

static std::vector<PseudoLabelData> labels;

void ARMRelocateSingleInst(int32_t inst, uint32_t cur_pc, TurboAssembler &turbo_assembler) {
  bool rewrite_flag = false;
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
      // ===
      _ Ldr(regRt, &PseudoDataLabel);
      _ ldr(regRt, MemOperand(regRt));
      // ===
      // Record the pseudo label to realized at the last.
      labels.push_back({PseudoDataLabel, target_address});
      rewrite_flag = true;
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
          // ===
          _ Ldr(regRd, &PseudoDataLabel);
          // ===
          // Record the pseudo label to realized at the last.
          labels.push_back({PseudoDataLabel, target_address});
          rewrite_flag = true;
        } while (0);

        // EXample
        if (opc == 0b111 && S == 0b1 && Rn == 0b1111) {
          // do something
        }
      }
    }
  }

  // Branch, branch with link, and block data transfer
  if ((op0 & 0b110) == 0b100) {
    uint32_t cond, op0;
    cond = bits(inst, 28, 31);
    op0  = bit(inst, 25);
    // Branch (immediate)
    if (op0 == 1) {
      uint32_t cond = 0, H = 0, imm24 = 0;
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

        // ===
        // just modify oriign instruction label bits, and keep the link and cond bits, the next instruction `b_imm` will do the rest work.
        label = 0x4;
        imm24 = label >> 2;
        _ Emit((inst & 0xff000000) | imm24);
        if (flag_link) {
          _ bl(0);
          _ b(4);
        } else {
          _ b(4);
        }
        _ ldr(pc, MemOperand(pc, -4));
        _ Emit(target_address);
        rewrite_flag = true;
      } while (0);
    }
  }

  // if the inst do not needed relocate, just rewrite the origin
  if (!rewrite_flag) {
    _ Emit(inst);
  }
}

// =====

// relocate thumb-1 instructions
void Thumb1RelocateSingleInst(int16_t inst, uint32_t cur_pc, CustomThumbTurboAssembler &turbo_assembler) {
  bool rewrite_flag = false;
  uint32_t val = 0, op = 0, rm = 0, rn = 0, rd = 0, shift = 0, cond = 0;
  int32_t offset = 0;

  // adr
  if ((inst & 0xf800) == 0xa000) {
    rd            = bits(inst, 8, 10);
    uint16_t imm8 = bits(inst, 0, 7);
    val           = cur_pc + imm8;

    if (cur_pc % 4)
      _ t1_nop();

    CustomThumbPseudoLabel label;
    // ===
    _ T2_Ldr(Register::from_code(rd), &label);
    // ===
    labels.push_back({label, val});
    rewrite_flag = true;
  }

  if ((inst & 0xf000) == 0xd000) {
    uint16_t cond = bits(inst, 8, 11);
    // cond != 111x
    if (cond >= 0b1110) {
      UNREACHABLE();
    }
    uint16_t imm8   = bits(inst, 0, 7);
    uint32_t offset = imm8 << 2;
    val             = cur_pc + offset;

    if (cur_pc % 4)
      _ t1_nop();

    CustomThumbPseudoLabel label;
    // modify imm8 field
    imm8 = 0x4 >> 2;
    // ===
    _ EmitInt16((inst & 0xfff0) | imm8);
    _ t1_nop();
    _ t1_b(0);
    _ T2_Ldr(pc, &label);
    // ===
    labels.push_back({label, val});
    rewrite_flag = true;
  }

  // compare branch (cbz, cbnz)
  if ((inst & 0xf500) == 0xb100) {
    uint16_t imm5   = bits(inst, 3, 7);
    uint16_t i      = bit(inst, 9);
    uint32_t offset = (i << 6) | (imm5 << 1);
    val             = cur_pc + offset;

    rn = bits(inst, 0, 2);

    if (cur_pc % 4)
      _ t1_nop();

    CustomThumbPseudoLabel label;
    // ===
    imm5 = bits(0x4 >> 1, 1, 5);
    i    = bit(0x4 >> 1, 6);
    _ EmitInt16((inst & 0xfd07) | imm5 << 3 | i << 9);
    _ t1_nop();
    _ t1_b(0);
    _ T2_Ldr(pc, &label);
    // ===
    labels.push_back({label, val});
    rewrite_flag = true;
  }

  // unconditional branch
  if ((inst & 0xf800) == 0xe000) {
    uint16_t imm11  = bits(inst, 0, 10);
    uint32_t offset = imm11 << 1;
    val             = cur_pc + offset;

    if (cur_pc % 4)
      _ t1_nop();

    CustomThumbPseudoLabel label;
    // ===
    _ T2_Ldr(pc, &label);
    // ===
    labels.push_back({label, val});
    rewrite_flag = true;
  }

  // if the inst do not needed relocate, just rewrite the origin
  if (!rewrite_flag) {
    _ EmitInt16(inst);
  }
}

void Thumb2RelocateSingleInst(int16_t inst1, int16_t inst2, uint32_t cur_pc,
                              CustomThumbTurboAssembler &turbo_assembler) {

  bool rewrite_flag = false;
  // Branches and miscellaneous control
  if ((inst1 & 0xf800) == 0xf000 && (inst2 & 0x8000) == 0x8000) {
    int32_t op1 = 0, op3 = 0;
    op1 = bits(inst1, 6, 9);
    op3 = bits(inst2, 12, 14);
    if (op1 >= 0b1110)
      return;

    // B-T3
    if (op3 == 0b000 || op3 == 0b010) {

      int S     = sbits(inst1, 10, 10);
      int J1    = bit(inst2, 13);
      int J2    = bit(inst2, 11);
      int imm6  = bits(inst1, 0, 5);
      int imm11 = bits(inst2, 0, 10);

      int32_t label = (imm11 << 1) | (imm6 << 12) | (J1 << 18) | (J2 << 19) | (S << 20);
      int32_t val   = cur_pc + label + Thumb_PC_OFFSET;
      
      if (cur_pc % 4)
        _ t1_nop();
      // ===
      imm11 = 0x4 >> 1;
      _ EmitInt16(inst1 & 0xffc0); // clear imm6
      _ EmitInt16(inst2 & 0xd000 | imm11); // 1. clear J1, J2, origin_imm12 2. set new imm11
      
      _ t2_b(0x0);
      _ t2_ldr(pc, MemOperand(pc, -4));
      _ Emit(val);
      // ===
      rewrite_flag = true;
    }

    // B-T4
    if (op3 == 0b001 || op3 == 0b011) {
      int S     = sbits(inst1, 10, 10);
      int J1    = bit(inst2, 13);
      int J2    = bit(inst2, 11);
      int imm10 = bits(inst1, 0, 9);
      int imm11 = bits(inst2, 0, 10);
      int i1    = !(J1 ^ S);
      int i2    = !(J2 ^ S);

      int32_t label = (imm11 << 1) | (imm10 << 12) | (J1 << 22) | (J2 << 23) | (S << 24);
      int32_t val   = cur_pc + label;
      
      if (cur_pc % 4)
        _ t1_nop();
      // ===
      _ t2_ldr(pc, MemOperand(pc, -4));
      _ Emit(val);
      // ===
      rewrite_flag = true;
    }

    // BL, BLX (immediate) - T1 variant
    if (op3 == 0b100 || op3 == 0b110) {
      int S         = sbits(inst1, 10, 10);
      int J1        = bit(inst2, 13);
      int J2        = bit(inst2, 11);
      int i1        = !(J1 ^ S);
      int i2        = !(J2 ^ S);
      int imm11     = bits(inst2, 0, 10);
      int imm10     = bits(inst1, 0, 9);
      int32_t label = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (S << 24);
      int32_t val   = cur_pc + label;

      // =====
      _ t2_bl(0);
      _ t2_b(0);
      _ t2_ldr(pc, MemOperand(pc, -4));
      _ Emit(val);
      // =====
      rewrite_flag = true;
    }

    // BL, BLX (immediate) - T2 variant
    if (op3 == 0b101 || op3 == 0b111) {
      int S         = sbits(inst1, 10, 10);
      int J1        = bit(inst2, 13);
      int J2        = bit(inst2, 11);
      int i1        = !(J1 ^ S);
      int i2        = !(J2 ^ S);
      int imm10h    = bits(inst1, 0, 9);
      int imm10l    = bits(inst2, 1, 10);
      int32_t label = (imm10l << 2) | (imm10h << 12) | (i2 << 22) | (i1 << 23) | (S << 24);
      int32_t val   = cur_pc + label;

      // =====
      _ t2_bl(0);
      _ t2_b(0);
      _ t2_ldr(pc, MemOperand(pc, -4));
      _ Emit(val);
      // =====
      rewrite_flag = true;
    }
  }

  // Data-processing (simple immediate)
  if ((inst1 & 0xfb50) == 0xf200 & (inst2 & 0x8000) == 0) {
    int o1 = bit(inst1, 7);
    int o2 = bit(inst1, 5);
    int rn = bits(inst1, 0, 3);

    uint32_t i     = bit(inst1, 10);
    uint32_t imm3  = bits(inst2, 12, 14);
    uint32_t imm8  = bits(inst2, 0, 7);
    uint32_t rd = bits(inst2, 8, 11);
    uint32_t label = imm8 | (imm3 << 8) | (i << 11);
    int32_t val    = 0;
    
    if (rn == 15 && o1 == 0 && o2 == 0) {
      // ADR - T3 variant
      // adr with add
      val = cur_pc + label;
    } else if (rn == 15 && o1 == 1 && o2 == 1) {
      // ADR - T2 variant
      // adr with sub
      val = cur_pc - label;
    }

    // ===
    _ t2_ldr(Register::from_code(rd), MemOperand(pc, -4));
    _ Emit(val);
    // ===
    rewrite_flag = true;
  }

  // Load literal
  if ((inst1 & 0xff0f) == 0xf85f) {
    uint32_t U     = bit(inst1, 7);
    uint32_t imm12 = bits(inst2, 0, 11);
    uint16_t rt    = bits(inst2, 12, 15);

    uint32_t label = imm12;
    int32_t val    = 0;
    if (U == 1) {
      val = val + label;
    } else {
      val = val - label;
    }

    Register regRt = Register::from_code(rt);
    // =====
    _ t2_ldr(regRt, MemOperand(pc, -4));
    _ t2_ldr(regRt, MemOperand(regRt, 0));
    // =====
    rewrite_flag = true;
  }

  // if the inst do not needed relocate, just rewrite the origin
  if (!rewrite_flag) {
    _ EmitInt16(inst1);
    _ EmitInt16(inst2);
  }
}

// =====

AssemblerCode *gen_arm_relocate_code(uintptr_t aligned_src_pc, int *relocate_size) {
  uintptr_t cur_pc = aligned_src_pc;
  uint32_t inst    = *(uint32_t *)aligned_src_pc;

  TurboAssembler turbo_assembler_;
#define _ turbo_assembler_.
  while (cur_pc < (aligned_src_pc + *relocate_size)) {
    ARMRelocateSingleInst(inst, cur_pc, turbo_assembler_);
    DLOG("[*] relocate arm inst: 0x%x\n", inst);
    // Move to next instruction
    cur_pc += 4;
    inst = *(uint32_t *)cur_pc;
  }

  // Branch to the rest of instructions
  CodeGen codegen(&turbo_assembler_);
  codegen.LiteralLdrBranch(cur_pc + 4);

  // Realize all the Pseudo-Label-Data
  for (auto it : labels) {
    _ PseudoBind(&(it.label));
    _ Emit(it.address);
  }
  AssemblerCode *code = AssemblerCode::FinalizeTurboAssembler(&turbo_assembler_);
  return code;
}

AssemblerCode *gen_thumb_relocate_code(uintptr_t aligned_src_pc, int *relocate_size) {
  uintptr_t cur_pc         = aligned_src_pc;
  uint32_t inst            = *(uint32_t *)aligned_src_pc;
  int actual_relocate_size = 0;
  CustomThumbTurboAssembler turbo_assembler_;
#define _ turbo_assembler_.
  while (cur_pc < (aligned_src_pc + *relocate_size)) {
    if (is_thumb2(inst)) {
      Thumb2RelocateSingleInst((int16_t)inst, (int16_t)(inst >> 16), cur_pc, turbo_assembler_);
      DLOG("[*] relocate thumb2 inst: 0x%x\n", inst);

      // Move to next instruction
      cur_pc += 4;
      actual_relocate_size += 4;
      inst = *(uint32_t *)cur_pc;
    } else {
      Thumb1RelocateSingleInst((int16_t)inst, cur_pc, turbo_assembler_);
      DLOG("[*] relocate thumb1 inst: 0x%x\n", (uint16_t)inst);

      // Move to next instruction
      cur_pc += 2;
      actual_relocate_size += 2;
      inst = *(uint32_t *)cur_pc;
    }
  }

  // set the actual relocate instruction size;
  *relocate_size = actual_relocate_size;

  if (cur_pc % 4) {
    _ t1_nop();
  }
  _ t2_ldr(pc, MemOperand(pc, -4));
  _ Emit(cur_pc + Thumb_PC_OFFSET);

  AssemblerCode *code = AssemblerCode::FinalizeTurboAssembler(&turbo_assembler_);
  return code;
}

Code *GenRelocateCode(uintptr_t src_pc, int *relocate_size) {
  uword aligned_pc = ThumbAlign(src_pc);

  bool is_thumb = src_pc % 2;

  AssemblerCode *code = NULL;
  if (is_thumb) {
    code = gen_thumb_relocate_code(aligned_pc, relocate_size);
  } else {
    code = gen_arm_relocate_code(aligned_pc, relocate_size);
  }
  return code;
}

} // namespace arm
} // namespace zz
