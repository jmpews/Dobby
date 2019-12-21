#include "InstructionRelocation/arm/ARMInstructionRelocation.h"

#include "core/arch/arm/registers-arm.h"
#include "core/modules/assembler/assembler-arm.h"
#include "core/modules/codegen/codegen-arm.h"

#define TEMP_REG r12

using namespace zz;
using namespace zz::arm;

static bool is_thumb2(uint32_t inst) {
  uint16_t inst1, inst2;
  inst1 = inst & 0x0000ffff;
  inst2 = (inst & 0xffff0000) >> 16;
  // refer: Top level T32 instruction set encoding
  uint32_t op0 = bits(inst1, 13, 15);
  uint32_t op1 = bits(inst1, 11, 12);

  if (op0 == 0b111 && op1 != 0b00) {
    return true;
  }
  return false;
}

typedef struct _PseudoLabelData {
  PseudoLabel label;
  uint32_t address;
} PseudoLabelData;

typedef struct _CustomThumbPseudoLabelData {
  CustomThumbPseudoLabel label;
  uint32_t address;
} CustomThumbPseudoLabelData;

// TODO: NOT THREAD SAFE!!!
#if 0
static std::vector<PseudoLabelData> labels;
static std::vector<CustomThumbPseudoLabelData> thumb_labels;
#endif
LiteMutableArray *labels;
LiteMutableArray *thumb_labels;

void ARMRelocateSingleInst(int32_t inst, uint32_t from_pc, uint32_t to_pc, TurboAssembler &turbo_assembler) {
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
      uint32_t target_address          = imm12 + from_pc;
      Register regRt                   = Register::R(Rt);
      PseudoLabelData *pseudoDataLabel = new PseudoLabelData;
      pseudoDataLabel->address         = target_address;
      // ===
      _ Ldr(regRt, &pseudoDataLabel->label);
      _ ldr(regRt, MemOperand(regRt));
      // ===
      // Record the pseudo label to realized at the last.
      labels->pushObject((LiteObject *)pseudoDataLabel);
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
            target_address = from_pc - imm12;
          } else if (opc == 0b100 && S == 0b0 && Rn == 0b1111) {
            // ADR - A1 variant
            // add = TRUE
            target_address = from_pc + imm12;
          } else
            break;

          Register regRd                   = Register::R(Rd);
          PseudoLabelData *pseudoDataLabel = new PseudoLabelData;
          pseudoDataLabel->address         = target_address;
          // ===
          _ Ldr(regRd, &pseudoDataLabel->label);
          // ===
          // Record the pseudo label to realized at the last.
          labels->pushObject((LiteObject *)pseudoDataLabel);
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
        uint32_t target_address = from_pc + label;
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
        // just modify orin instruction label bits, and keep the link and cond bits, the next instruction `b_imm` will
        // do the rest work.
        label = 0x4;
        imm24 = label >> 2;
        _ EmitARMInst((inst & 0xff000000) | imm24);
        if (flag_link) {
          _ bl(0);
          _ b(4);
        } else {
          _ b(4);
        }
        _ ldr(pc, MemOperand(pc, -4));
        _ EmitAddress(target_address);
        rewrite_flag = true;
      } while (0);
    }
  }

  // if the inst do not needed relocate, just rewrite the origin
  if (!rewrite_flag) {
    _ EmitARMInst(inst);
  }
}

// =====

// relocate thumb-1 instructions
void Thumb1RelocateSingleInst(int16_t inst, uint32_t from_pc, uint32_t to_pc,
                              CustomThumbTurboAssembler &turbo_assembler) {
  bool rewrite_flag = false;
  uint32_t val = 0, op = 0, rt = 0, rm = 0, rn = 0, rd = 0, shift = 0, cond = 0;
  int32_t offset = 0;

  // [F3.2.3 Special data instructions and branch and exchange]
  // [Add, subtract, compare, move (two high registers)]
  if ((inst & 0xfc00) == 0x4400) {
    int rs = bits(inst, 3, 6);
    // rs is PC register
    if (rs == 15) {
      val = from_pc;

      uint16_t rewrite_inst = 0;
      rewrite_inst          = (inst & 0xff87) | LFT((TEMP_REG.code()), 4, 3);

      CustomThumbPseudoLabelData *customPseudoDataLabel = new CustomThumbPseudoLabelData;
      customPseudoDataLabel->address                    = val;
      // ===
      _ T2_Ldr(TEMP_REG, &customPseudoDataLabel->label);
      _ EmitInt16(rewrite_inst);
      // ===
      thumb_labels->pushObject((LiteObject *)customPseudoDataLabel);
      rewrite_flag = true;
    }
  }

  // ldr literal
  if ((inst & 0xf800) == 0x4800) {
    int32_t imm8   = bits(inst, 0, 7);
    int32_t offset = imm8 << 2;
    val            = from_pc + offset;
    val            = ALIGN_FLOOR(val, 4);
    rt             = bits(inst, 8, 10);

    CustomThumbPseudoLabelData *customPseudoDataLabel = new CustomThumbPseudoLabelData;
    customPseudoDataLabel->address                    = val;
    // ===
    _ T2_Ldr(Register::R(rt), &customPseudoDataLabel->label);
    _ t2_ldr(Register::R(rt), MemOperand(Register::R(rt), 0));
    // ===
    thumb_labels->pushObject((LiteObject *)customPseudoDataLabel);
    rewrite_flag = true;
  }

  // adr
  if ((inst & 0xf800) == 0xa000) {
    rd            = bits(inst, 8, 10);
    uint16_t imm8 = bits(inst, 0, 7);
    val           = from_pc + imm8;

    CustomThumbPseudoLabelData *customPseudoDataLabel = new CustomThumbPseudoLabelData;
    customPseudoDataLabel->address                    = val;
    // ===
    _ T2_Ldr(Register::R(rd), &customPseudoDataLabel->label);
    // ===
    if (pc.code() == rd)
      val += 1;
    thumb_labels->pushObject((LiteObject *)customPseudoDataLabel);
    rewrite_flag = true;
  }

  // b
  if ((inst & 0xf000) == 0xd000) {
    uint16_t cond = bits(inst, 8, 11);
    // cond != 111x
    if (cond >= 0b1110) {
      UNREACHABLE();
    }
    uint16_t imm8   = bits(inst, 0, 7);
    uint32_t offset = imm8 << 1;
    val             = from_pc + offset;

    CustomThumbPseudoLabelData *customPseudoDataLabel = new CustomThumbPseudoLabelData;
    customPseudoDataLabel->address                    = val + 1;
    // modify imm8 field
    imm8 = 0x4 >> 1;
    // ===
    _ EmitInt16((inst & 0xfff0) | imm8);
    _ t1_nop();
    _ t2_b(4);
    _ T2_Ldr(pc, &customPseudoDataLabel->label);
    // ===
    thumb_labels->pushObject((LiteObject *)customPseudoDataLabel);
    rewrite_flag = true;
  }

  // compare branch (cbz, cbnz)
  if ((inst & 0xf500) == 0xb100) {
    uint16_t imm5   = bits(inst, 3, 7);
    uint16_t i      = bit(inst, 9);
    uint32_t offset = (i << 6) | (imm5 << 1);
    val             = from_pc + offset;
    rn              = bits(inst, 0, 2);

    CustomThumbPseudoLabelData *customPseudoDataLabel = new CustomThumbPseudoLabelData;
    customPseudoDataLabel->address                    = val + 1;

    imm5 = bits(0x4 >> 1, 1, 5);
    i    = bit(0x4 >> 1, 6);
    // ===
    _ EmitInt16((inst & 0xfd07) | imm5 << 3 | i << 9);
    _ t2_b(0);
    _ T2_Ldr(pc, &customPseudoDataLabel->label);
    // ===
    thumb_labels->pushObject((LiteObject *)customPseudoDataLabel);
    rewrite_flag = true;
  }

  // unconditional branch
  if ((inst & 0xf800) == 0xe000) {
    uint16_t imm11  = bits(inst, 0, 10);
    uint32_t offset = imm11 << 1;
    val             = from_pc + offset;

    CustomThumbPseudoLabelData *customPseudoDataLabel = new CustomThumbPseudoLabelData;
    customPseudoDataLabel->address                    = val + 1;
    // ===
    _ T2_Ldr(pc, &customPseudoDataLabel->label);
    // ===
    thumb_labels->pushObject((LiteObject *)customPseudoDataLabel);
    rewrite_flag = true;
  }

  // if the inst do not needed relocate, just rewrite the origin
  if (!rewrite_flag) {
#if 0
        if (from_pc % Thumb2_INST_LEN)
            _ t1_nop();
#endif
    _ EmitInt16(inst);
  }
}

void Thumb2RelocateSingleInst(int16_t inst1, int16_t inst2, uint32_t from_pc, uint32_t to_pc,
                              CustomThumbTurboAssembler &turbo_assembler) {

  bool rewrite_flag = false;
  // Branches and miscellaneous control
  if ((inst1 & 0xf800) == 0xf000 && (inst2 & 0x8000) == 0x8000) {
    int32_t op1 = 0, op3 = 0;
    op1 = bits(inst1, 6, 9);
    op3 = bits(inst2, 12, 14);

    // B-T3 AKA b.cond
    if (((op1 & 0b1110) != 0b1110) && ((op3 & 0b101) == 0b000)) {

      int S     = sbits(inst1, 10, 10);
      int J1    = bit(inst2, 13);
      int J2    = bit(inst2, 11);
      int imm6  = bits(inst1, 0, 5);
      int imm11 = bits(inst2, 0, 10);

      int32_t label = (S << 20) | (J2 << 19) | (J1 << 18) | (imm6 << 12) | (imm11 << 1);
      uint32_t val  = from_pc + label;

      // ===
      imm11 = 0x4 >> 1;
      _ EmitInt16(inst1 & 0xffc0);           // clear imm6
      _ EmitInt16((inst2 & 0xd000) | imm11); // 1. clear J1, J2, origin_imm12 2. set new imm11

      _ t2_b(4);
      _ t2_ldr(pc, MemOperand(pc, 0));
      _ EmitAddress(val + THUMB_ADDRESS_FLAG);
      // ===
      rewrite_flag = true;
    }

    // B-T4 AKA b.w
    if ((op3 & 0b101) == 0b001) {
      int S     = sbits(inst1, 10, 10);
      int J1    = bit(inst2, 13);
      int J2    = bit(inst2, 11);
      int imm10 = bits(inst1, 0, 9);
      int imm11 = bits(inst2, 0, 10);
      int i1    = !(J1 ^ S);
      int i2    = !(J2 ^ S);

      int32_t label = (S << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
      int32_t val   = from_pc + label;

      // ===
      _ t2_ldr(pc, MemOperand(pc, 0));
      _ EmitAddress(val + THUMB_ADDRESS_FLAG);
      // ===
      rewrite_flag = true;
    }

    // BL, BLX (immediate) - T1 variant AKA bl
    if ((op3 & 0b101) == 0b101) {
      int S     = bit(inst1, 10);
      int J1    = bit(inst2, 13);
      int J2    = bit(inst2, 11);
      int i1    = !(J1 ^ S);
      int i2    = !(J2 ^ S);
      int imm11 = bits(inst2, 0, 10);
      int imm10 = bits(inst1, 0, 9);
      // S is sign-bit, '-S' maybe not better
      int32_t label = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (-S << 24);
      int32_t val   = from_pc + label;

      // =====
      _ t2_bl(4);
      _ t2_b(8);
      _ t2_ldr(pc, MemOperand(pc, 0));
      _ EmitAddress(val + THUMB_ADDRESS_FLAG);
      // =====
      rewrite_flag = true;
    }

    // BL, BLX (immediate) - T2 variant AKA blx
    if ((op3 & 0b101) == 0b100) {
      int S      = bit(inst1, 10);
      int J1     = bit(inst2, 13);
      int J2     = bit(inst2, 11);
      int i1     = !(J1 ^ S);
      int i2     = !(J2 ^ S);
      int imm10h = bits(inst1, 0, 9);
      int imm10l = bits(inst2, 1, 10);
      // S is sign-bit, '-S' maybe not better
      int32_t label = (imm10l << 2) | (imm10h << 12) | (i2 << 22) | (i1 << 23) | (-S << 24);
      uint32_t val  = from_pc + label;

      // =====
      _ t2_bl(4);
      _ t2_b(8);
      _ t2_ldr(pc, MemOperand(pc, 0));
      _ EmitAddress(val);
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
    uint32_t rd    = bits(inst2, 8, 11);
    uint32_t label = imm8 | (imm3 << 8) | (i << 11);
    int32_t val    = 0;

    if (rn == 15 && o1 == 0 && o2 == 0) {
      // ADR - T3 variant
      // adr with add
      val = from_pc + label;
    } else if (rn == 15 && o1 == 1 && o2 == 1) {
      // ADR - T2 variant
      // adr with sub
      val = from_pc - label;
    }

    // ===
    _ t2_ldr(Register::R(rd), MemOperand(pc, 4));
    _ t2_b(0);
    _ EmitAddress(val);
    // ===
    rewrite_flag = true;
  }

  // LDR literal (T2)
  if ((inst1 & 0xff7f) == 0xf85f) {
    uint32_t U     = bit(inst1, 7);
    uint32_t imm12 = bits(inst2, 0, 11);
    uint16_t rt    = bits(inst2, 12, 15);

    uint32_t label = imm12;
    int32_t val    = 0;
    if (U == 1) {
      val = from_pc + label;
    } else {
      val = from_pc - label;
    }

    val = ALIGN_FLOOR(val, 4);

    Register regRt = Register::R(rt);
    // =====
    _ t2_ldr(regRt, MemOperand(pc, 4));
    _ t2_b(4);
    _ EmitAddress(val);
    _ t2_ldr(regRt, MemOperand(regRt, 0));
    // =====
    rewrite_flag = true;
  }

  // if the inst do not needed relocate, just rewrite the origin
  if (!rewrite_flag) {
#if 0
        if (from_pc % Thumb2_INST_LEN)
            _ t1_nop();
#endif
    _ EmitInt16(inst1);
    _ EmitInt16(inst2);
  }
}

// =====

AssemblyCode *gen_arm_relocate_code(void *buffer, int *relocate_size, uint32_t from_pc, uint32_t to_pc) {
  uint32_t cur_addr    = (uint32_t)buffer;
  uint32_t cur_src_pc  = from_pc + ARM_PC_OFFSET;
  uint32_t cur_dest_pc = to_pc + ARM_PC_OFFSET;
  uint32_t inst        = *(uint32_t *)cur_addr;

  TurboAssembler turbo_assembler_(0);
#undef _
#define _ turbo_assembler_.
  while (cur_addr < ((uint32_t)buffer + *relocate_size)) {
    int off = turbo_assembler_.GetCodeBuffer()->getSize();
    ARMRelocateSingleInst(inst, cur_src_pc, cur_dest_pc, turbo_assembler_);
    DLOG("[*] relocate arm inst: 0x%x\n", inst);
    // Move to next instruction
    cur_src_pc += ARM_INST_LEN;
    cur_dest_pc += turbo_assembler_.GetCodeBuffer()->getSize() - off;
    cur_addr += ARM_INST_LEN;
    inst = *(uint32_t *)cur_addr;
  }

  // Branch to the rest of instructions
  CodeGen codegen(&turbo_assembler_);
  // next instruction address  == cur_addr
  codegen.LiteralLdrBranch(cur_addr);

#if 0
  // Realize all the Pseudo-Label-Data
  for (auto it : labels) {
    _ PseudoBind(&(it.label));
    _ Emit(it.address);
  }
#endif
  // Realize all the Pseudo-Label-Data
  PseudoLabelData *it;
  LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(labels);
  while ((it = reinterpret_cast<PseudoLabelData *>(iter->getNextObject())) != NULL) {
    _ PseudoBind(&(it->label));
    _ EmitAddress(it->address);
  }

  AssemblyCode *code = AssemblyCode::FinalizeFromTurboAssember(&turbo_assembler_);
  return code;
}

AssemblyCode *gen_thumb_relocate_code(void *buffer, int *relocate_size, uint32_t from_pc, uint32_t to_pc) {
  uint32_t cur_addr        = (uint32_t)buffer;
  uint32_t cur_src_pc      = from_pc + Thumb_PC_OFFSET;
  uint32_t cur_dest_pc     = to_pc + Thumb_PC_OFFSET;
  uint32_t inst            = *(uint32_t *)cur_addr;
  int actual_relocate_size = 0;
  CustomThumbTurboAssembler turbo_assembler_(0);
#define _ turbo_assembler_.

  // put nop if the first instruction type is thumb1
  if (cur_src_pc % Thumb2_INST_LEN)
    _ t1_nop();

  while (cur_addr < ((uint32_t)buffer + *relocate_size)) {
    // align nop
    _ AlignThumbNop();

    int off = turbo_assembler_.GetCodeBuffer()->getSize();
    if (is_thumb2(inst)) {
      Thumb2RelocateSingleInst((uint16_t)inst, (uint16_t)(inst >> 16), cur_src_pc, cur_dest_pc, turbo_assembler_);
      DLOG("[*] relocate thumb2 inst: 0x%x\n", inst);

      // Move to next instruction
      cur_src_pc += Thumb2_INST_LEN;
      cur_addr += Thumb2_INST_LEN;
      actual_relocate_size += Thumb2_INST_LEN;
    } else {
      Thumb1RelocateSingleInst((uint16_t)inst, cur_src_pc, cur_dest_pc, turbo_assembler_);
      DLOG("[*] relocate thumb1 inst: 0x%x\n", (uint16_t)inst);

      // Move to next instruction
      cur_src_pc += Thumb1_INST_LEN;
      cur_addr += Thumb1_INST_LEN;
      actual_relocate_size += Thumb1_INST_LEN;
    }
    cur_dest_pc += turbo_assembler_.GetCodeBuffer()->getSize() - off;
    inst = *(uint32_t *)cur_addr;
  }

  // set the actual relocate instruction size, as the thumb1 || thumb2 cause  relocate_size != actual_relocate_size
  *relocate_size = actual_relocate_size;

  _ AlignThumbNop();

  // Branch to the rest of instructions
  _ t2_ldr(pc, MemOperand(pc, 0));
  _ EmitAddress(cur_addr + THUMB_ADDRESS_FLAG);

#if 0
  // Realize all the Pseudo-Label-Data
  for (auto it : thumb_labels) {
    _ CustomThumbPseudoBind(&(it.label));
    _ Emit(it.address);
  }
#endif

  // Realize all the Pseudo-Label-Data
  CustomThumbPseudoLabelData *it;
  LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(thumb_labels);
  while ((it = reinterpret_cast<CustomThumbPseudoLabelData *>(iter->getNextObject())) != NULL) {
    _ CustomThumbPseudoBind(&(it->label));
    _ EmitAddress(it->address);
  }

  AssemblyCode *code = AssemblyCode::FinalizeFromTurboAssember(&turbo_assembler_);
  return code;
}

AssemblyCode *GenRelocateCode(void *buffer, int *relocate_size, addr_t from_pc, addr_t to_pc) {
  from_pc = (addr_t)buffer;

  bool is_thumb      = (uint32_t)buffer % 2;
  AssemblyCode *code = NULL;

  buffer = (void *)(ALIGN(buffer, 2));

  // Clear labels cache, Not-Thread-Safe
  // TODO:
  // labels.clear();
  // thumb_labels.clear();

  if (is_thumb) {
    code = gen_thumb_relocate_code(buffer, relocate_size, from_pc, to_pc);
  } else {
    code = gen_arm_relocate_code(buffer, relocate_size, from_pc, to_pc);
  }
  return code;
}
