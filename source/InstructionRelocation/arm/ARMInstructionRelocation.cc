#include "./ARMInstructionRelocation.h"

#include "dobby_internal.h"

#include "core/arch/arm/registers-arm.h"
#include "core/modules/assembler/assembler-arm.h"
#include "core/modules/codegen/codegen-arm.h"

#define TEMP_REG r12

using namespace zz;
using namespace zz::arm;

static bool is_thumb2(uint32_t instr) {
  uint16_t inst1, inst2;
  inst1 = instr & 0x0000ffff;
  inst2 = (instr & 0xffff0000) >> 16;
  // refer: Top level T32 instruction set encoding
  uint32_t op0 = bits(inst1, 13, 15);
  uint32_t op1 = bits(inst1, 11, 12);

  if (op0 == 0b111 && op1 != 0b00) {
    return true;
  }
  return false;
}

static void ARMRelocateSingleInstr(TurboAssembler &turbo_assembler, int32_t instr, uint32_t from_pc, uint32_t to_pc) {
  bool is_instr_relocated = false;
#define _ turbo_assembler.
  // top level encoding
  uint32_t cond, op0, op1;
  cond = bits(instr, 28, 31);
  op0  = bits(instr, 25, 27);
  op1  = bit(instr, 4);
  // Load/Store Word, Unsigned byte (immediate, literal)
  if (cond != 0b1111 && op0 == 0b010) {
    uint32_t P, U, o2, W, o1, Rn, Rt, imm12;
    P            = bit(instr, 24);
    W            = bit(instr, 21);
    imm12        = bits(instr, 0, 11);
    Rn           = bits(instr, 16, 19);
    Rt           = bits(instr, 12, 15);
    o1           = bit(instr, 20);
    o2           = bit(instr, 22);
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
      uint32_t target_address = imm12 + from_pc;
      Register regRt          = Register::R(Rt);

      RelocLabelEntry *pseudoDataLabel = new RelocLabelEntry(target_address);
      _ AppendRelocLabelEntry(pseudoDataLabel);

      // ===
      _ Ldr(regRt, pseudoDataLabel);
      _ ldr(regRt, MemOperand(regRt));
      // ===
      is_instr_relocated = true;
    } while (0);
  }

  // Data-processing and miscellaneous instructions
  if (cond != 0b1111 && (op0 & 0b110) == 0b000) {
    uint32_t op0, op1, op2, op3, op4;
    op0 = bit(instr, 25);
    // Data-processing immediate
    if (op0 == 1) {
      uint32_t op0, op1;
      op0 = bits(instr, 23, 24);
      op1 = bits(instr, 20, 21);
      // Integer Data Processing (two register and immediate)
      if ((op0 & 0b10) == 0b00) {
        uint32_t opc, S, Rn;
        opc = bits(instr, 21, 23);
        S   = bit(instr, 20);
        Rn  = bits(instr, 16, 19);
        do {
          uint32_t target_address;
          int Rd    = bits(instr, 12, 15);
          int imm12 = bits(instr, 0, 11);
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
          RelocLabelEntry *pseudoDataLabel = new RelocLabelEntry(target_address);
          _ AppendRelocLabelEntry(pseudoDataLabel);
          // ===
          _ Ldr(regRd, pseudoDataLabel);
          // ===
          is_instr_relocated = true;
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
    cond = bits(instr, 28, 31);
    op0  = bit(instr, 25);
    // Branch (immediate)
    if (op0 == 1) {
      uint32_t cond = 0, H = 0, imm24 = 0;
      bool flag_link;
      do {
        int imm24               = bits(instr, 0, 23);
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
        _ EmitARMInst((instr & 0xff000000) | imm24);
        if (flag_link) {
          _ bl(0);
          _ b(4);
        } else {
          _ b(4);
        }
        _ ldr(pc, MemOperand(pc, -4));
        _ EmitAddress(target_address);
        is_instr_relocated = true;
      } while (0);
    }
  }

  // if the instr do not needed relocate, just rewrite the origin
  if (!is_instr_relocated) {
    _ EmitARMInst(instr);
  }
}

// relocate thumb-1 instructions
static void Thumb1RelocateSingleInstr(ThumbTurboAssembler &turbo_assembler, LiteMutableArray *thumb_labels,
                                      int16_t instr, addr32_t from_pc, addr32_t to_pc) {
  bool is_instr_relocated = false;
  uint32_t val = 0, op = 0, rt = 0, rm = 0, rn = 0, rd = 0, shift = 0, cond = 0;
  int32_t offset = 0;

  // [F3.2.3 Special data instructions and branch and exchange]
  // [Add, subtract, compare, move (two high registers)]
  if ((instr & 0xfc00) == 0x4400) {
    int rs = bits(instr, 3, 6);
    // rs is PC register
    if (rs == 15) {
      val = from_pc;

      uint16_t rewrite_inst = 0;
      rewrite_inst          = (instr & 0xff87) | LFT((TEMP_REG.code()), 4, 3);

      ThumbThumbRelocLabelEntry *label = new ThumbThumbRelocLabelEntry(val);
      _ AppendRelocLabelEntry(label);
      // ===
      _ T2_Ldr(TEMP_REG, label);
      _ EmitInt16(rewrite_inst);
      // ===
      is_instr_relocated = true;
    }
  }

  // ldr literal
  if ((instr & 0xf800) == 0x4800) {
    int32_t imm8   = bits(instr, 0, 7);
    int32_t offset = imm8 << 2;
    val            = from_pc + offset;
    val            = ALIGN_FLOOR(val, 4);
    rt             = bits(instr, 8, 10);

    ThumbThumbRelocLabelEntry *label = new ThumbThumbRelocLabelEntry(val);
    _ AppendRelocLabelEntry(label);

    // ===
    _ T2_Ldr(Register::R(rt), label);
    _ t2_ldr(Register::R(rt), MemOperand(Register::R(rt), 0));
    // ===
    is_instr_relocated = true;
  }

  // adr
  if ((instr & 0xf800) == 0xa000) {
    rd            = bits(instr, 8, 10);
    uint16_t imm8 = bits(instr, 0, 7);
    val           = from_pc + imm8;

    ThumbThumbRelocLabelEntry *label = new ThumbThumbRelocLabelEntry(val);
    _ AppendRelocLabelEntry(label);
    // ===
    _ T2_Ldr(Register::R(rd), label);
    // ===
    if (pc.code() == rd)
      val += 1;
    is_instr_relocated = true;
  }

  // b
  if ((instr & 0xf000) == 0xd000) {
    uint16_t cond = bits(instr, 8, 11);
    // cond != 111x
    if (cond >= 0b1110) {
      UNREACHABLE();
    }
    uint16_t imm8   = bits(instr, 0, 7);
    uint32_t offset = imm8 << 1;
    val             = from_pc + offset;

    ThumbThumbRelocLabelEntry *label = new ThumbThumbRelocLabelEntry(val + 1);
    _ AppendRelocLabelEntry(label);

    // modify imm8 field
    imm8 = 0x4 >> 1;
    // ===
    _ EmitInt16((instr & 0xfff0) | imm8);
    _ t1_nop();
    _ t2_b(4);
    _ T2_Ldr(pc, label);
    // ===
    is_instr_relocated = true;
  }

  // compare branch (cbz, cbnz)
  if ((instr & 0xf500) == 0xb100) {
    uint16_t imm5   = bits(instr, 3, 7);
    uint16_t i      = bit(instr, 9);
    uint32_t offset = (i << 6) | (imm5 << 1);
    val             = from_pc + offset;
    rn              = bits(instr, 0, 2);

    ThumbThumbRelocLabelEntry *label = new ThumbThumbRelocLabelEntry(val + 1);
    _ AppendRelocLabelEntry(label);

    imm5 = bits(0x4 >> 1, 1, 5);
    i    = bit(0x4 >> 1, 6);
    // ===
    _ EmitInt16((instr & 0xfd07) | imm5 << 3 | i << 9);
    _ t2_b(0);
    _ T2_Ldr(pc, label);
    // ===
    is_instr_relocated = true;
  }

  // unconditional branch
  if ((instr & 0xf800) == 0xe000) {
    uint16_t imm11  = bits(instr, 0, 10);
    uint32_t offset = imm11 << 1;
    val             = from_pc + offset;

    ThumbThumbRelocLabelEntry *label = new ThumbThumbRelocLabelEntry(val + 1);
    _ AppendRelocLabelEntry(label);

    // ===
    _ T2_Ldr(pc, label);
    // ===
    is_instr_relocated = true;
  }

  // if the instr do not needed relocate, just rewrite the origin
  if (!is_instr_relocated) {
#if 0
        if (from_pc % Thumb2_INST_LEN)
            _ t1_nop();
#endif
    _ EmitInt16(instr);
  }
}

static void Thumb2RelocateSingleInstr(ThumbTurboAssembler &turbo_assembler, LiteMutableArray *thumb_labels,
                                      thumb1_inst_t inst1, thumb1_inst_t inst2, addr32_t from_pc, addr32_t to_pc) {

  bool is_instr_relocated = false;

  if (turbo_assembler.pc_offset() % 4) {
    _ t1_nop();
  }

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
      addr32_t val  = from_pc + label;

      // ===
      imm11 = 0x4 >> 1;
      _ EmitInt16(inst1 & 0xffc0);           // clear imm6
      _ EmitInt16((inst2 & 0xd000) | imm11); // 1. clear J1, J2, origin_imm12 2. set new imm11

      _ t2_b(4);
      _ t2_ldr(pc, MemOperand(pc, 0));
      _ EmitAddress(val + THUMB_ADDRESS_FLAG);
      // ===
      is_instr_relocated = true;
    }

    // B-T4 AKA b.w
    if ((op3 & 0b101) == 0b001) {
      int S     = bit(inst1, 10);
      int J1    = bit(inst2, 13);
      int J2    = bit(inst2, 11);
      int imm10 = bits(inst1, 0, 9);
      int imm11 = bits(inst2, 0, 10);
      int i1    = !(J1 ^ S);
      int i2    = !(J2 ^ S);

      int32_t label = (-S << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
      addr32_t val  = from_pc + label;

      // ===
      _ t2_ldr(pc, MemOperand(pc, 0));
      _ EmitAddress(val + THUMB_ADDRESS_FLAG);
      // ===
      is_instr_relocated = true;
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
      addr32_t val  = from_pc + label;

      // =====
      _ t2_bl(4);
      _ t2_b(8);
      _ t2_ldr(pc, MemOperand(pc, 0));
      _ EmitAddress(val + THUMB_ADDRESS_FLAG);
      // =====
      is_instr_relocated = true;
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
      addr32_t val  = ALIGN(from_pc, 4) + label;

      // =====
      _ t2_bl(4);
      _ t2_b(8);
      _ t2_ldr(pc, MemOperand(pc, 0));
      _ EmitAddress(val);
      // =====
      is_instr_relocated = true;
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
    addr32_t val   = 0;

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
    is_instr_relocated = true;
  }

  // LDR literal (T2)
  if ((inst1 & 0xff7f) == 0xf85f) {
    uint32_t U     = bit(inst1, 7);
    uint32_t imm12 = bits(inst2, 0, 11);
    uint16_t rt    = bits(inst2, 12, 15);

    uint32_t label = imm12;
    addr32_t val   = 0;
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
    is_instr_relocated = true;
  }

  // if the instr do not needed relocate, just rewrite the origin
  if (!is_instr_relocated) {
#if 0
        if (from_pc % Thumb2_INST_LEN)
            _ t1_nop();
#endif
    _ EmitInt16(inst1);
    _ EmitInt16(inst2);
  }
}

void gen_arm_relocate_code(void *buffer, AssemblyCode *origin, AssemblyCode *relocated) {
  TurboAssembler turbo_assembler_(0);
#undef _
#define _ turbo_assembler_.

  addr32_t curr_orig_pc = origin->raw_instruction_start() + ARM_PC_OFFSET;
  addr32_t curr_relo_pc = relocated->raw_instruction_start() + ARM_PC_OFFSET;

  addr_t buffer_cursor = (addr_t)buffer;
  arm_inst_t instr     = *(arm_inst_t *)buffer_cursor;

  int predefined_relocate_size = origin->raw_instruction_size();

  while (buffer_cursor < ((addr_t)buffer + predefined_relocate_size)) {
    int last_relo_offset = turbo_assembler_.GetCodeBuffer()->getSize();

    ARMRelocateSingleInstr(turbo_assembler_, instr, curr_orig_pc, curr_relo_pc);
    DLOG("Relocate arm instr: 0x%x", instr);

    // Move to next instruction
    curr_orig_pc += ARM_INST_LEN;
    buffer_cursor += ARM_INST_LEN;

    {
      // 1 orignal instrution => ? relocated instruction
      int relo_offset = turbo_assembler_.GetCodeBuffer()->getSize();
      int relo_len    = relo_offset - last_relo_offset;
      curr_relo_pc += relo_len;
    }
    instr = *(arm_inst_t *)buffer_cursor;
  }

  // Branch to the rest of instructions
  CodeGen codegen(&turbo_assembler_);
  // Get the real branch address
  codegen.LiteralLdrBranch(curr_orig_pc - ARM_PC_OFFSET);

  // Realize all the Pseudo-Label-Data
  _ RelocFixup();

  // Generate executable code
  {
    AssemblyCode *code = NULL;
    code               = AssemblyCode::FinalizeFromTurboAssember(&turbo_assembler_);
    relocated->reInitWithAddressRange(code->raw_instruction_start(), code->raw_instruction_size());
    delete code;
  }
}

void gen_thumb_relocate_code(void *buffer, AssemblyCode *origin, AssemblyCode *relocated) {
  LiteMutableArray *thumb_labels = new LiteMutableArray;

  ThumbTurboAssembler turbo_assembler_(0);
#define _ turbo_assembler_.

  addr32_t curr_orig_pc = origin->raw_instruction_start() + Thumb_PC_OFFSET;
  addr32_t curr_relo_pc = relocated->raw_instruction_start() + Thumb_PC_OFFSET;

  addr_t buffer_cursor = (addr_t)buffer;
  thumb2_inst_t instr  = *(thumb2_inst_t *)buffer_cursor;

  int predefined_relocate_size = origin->raw_instruction_size();
  DLOG("Thumb relocate %d start >>>>>", predefined_relocate_size);

  while (buffer_cursor < ((addr_t)buffer + predefined_relocate_size)) {
    // align nop
    _ t1_nop();

    int last_relo_offset = turbo_assembler_.GetCodeBuffer()->getSize();
    if (is_thumb2(instr)) {
      Thumb2RelocateSingleInstr(turbo_assembler_, thumb_labels, (uint16_t)instr, (uint16_t)(instr >> 16), curr_orig_pc,
                                curr_relo_pc);
      DLOG("Relocate thumb2 instr: 0x%x", instr);

      // Move to next instruction
      curr_orig_pc += Thumb2_INST_LEN;
      buffer_cursor += Thumb2_INST_LEN;
    } else {
      Thumb1RelocateSingleInstr(turbo_assembler_, thumb_labels, (uint16_t)instr, curr_orig_pc, curr_relo_pc);
      DLOG("Relocate thumb1 instr: 0x%x", (uint16_t)instr);

      // Move to next instruction
      curr_orig_pc += Thumb1_INST_LEN;
      buffer_cursor += Thumb1_INST_LEN;
    }

    {
      // 1 orignal instrution => ? relocated instruction
      int relo_offset = turbo_assembler_.GetCodeBuffer()->getSize();
      int relo_len    = relo_offset - last_relo_offset;
      curr_relo_pc += relo_len;
    }
    instr = *(thumb2_inst_t *)buffer_cursor;
  }

  // Branch to the rest of instructions
  _ t2_ldr(pc, MemOperand(pc, 0));
  // Get the real branch address
  _ EmitAddress(curr_orig_pc - Thumb_PC_OFFSET + THUMB_ADDRESS_FLAG);

  // Realize all the Pseudo-Label-Data
  _ RelocFixup();

  // Generate executable code
  {
    AssemblyCode *code = NULL;
    code               = AssemblyCode::FinalizeFromTurboAssember(&turbo_assembler_);
    relocated->reInitWithAddressRange(code->raw_instruction_start(), code->raw_instruction_size());
    delete code;
  }
}

void GenRelocateCode(void *buffer, AssemblyCode *origin, AssemblyCode *relocated) {
  bool is_thumb = (addr32_t)origin->raw_instruction_start() % 2;
  if (is_thumb) {
    buffer = (void *)((addr_t)buffer - THUMB_ADDRESS_FLAG);

    // remove thumb address flag
    origin->reInitWithAddressRange(origin->raw_instruction_start() - THUMB_ADDRESS_FLAG,
                                   origin->raw_instruction_size());

    gen_thumb_relocate_code(buffer, origin, relocated);

    // add thumb address flag
    relocated->reInitWithAddressRange(relocated->raw_instruction_start() + THUMB_ADDRESS_FLAG,
                                      relocated->raw_instruction_size());
  } else {
    gen_arm_relocate_code(buffer, origin, relocated);
  }
}
