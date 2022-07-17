#include "platform_macro.h"
#if defined(TARGET_ARCH_ARM)

#include "dobby_internal.h"

#include "InstructionRelocation/arm/InstructionRelocationARM.h"

#include "core/arch/arm/registers-arm.h"
#include "core/assembler/assembler-arm.h"
#include "core/codegen/codegen-arm.h"

using namespace zz;
using namespace zz::arm;

typedef struct {
  addr_t mapped_addr;

  uint8_t *buffer;
  uint8_t *buffer_cursor;
  size_t buffer_size;

  vmaddr_t src_vmaddr;
  vmaddr_t dst_vmaddr;

  CodeMemBlock *relocated;
  CodeBuffer *relocated_buffer;

  ExecuteState start_state;
  ExecuteState curr_state;
  Assembler *curr_assembler;
  ThumbTurboAssembler *thumb_assembler;
  TurboAssembler *arm_assembler;

  tinystl::unordered_map<addr_t, ExecuteState> execute_state_map;

  tinystl::unordered_map<off_t, off_t> relocated_offset_map;

  tinystl::unordered_map<vmaddr_t, AssemblerPseudoLabel *> label_map;
} relo_ctx_t;

// ----- next -----

addr_t relo_cur_src_vmaddr(relo_ctx_t *ctx) {
  int relocated_len = ctx->buffer_cursor - ctx->buffer;
  if (ctx->curr_state == zz::arm::ARMExecuteState) {
    return ctx->src_vmaddr + relocated_len + ARM_PC_OFFSET;
  } else {
    return ctx->src_vmaddr + relocated_len + Thumb_PC_OFFSET;
  }
}

static bool is_thumb2(uint32_t insn) {
  uint16_t insn1, insn2;
  insn1 = insn & 0x0000ffff;
  insn2 = (insn & 0xffff0000) >> 16;
  // refer: Top level T32 insnuction set encoding
  uint32_t op0 = bits(insn1, 13, 15);
  uint32_t op1 = bits(insn1, 11, 12);

  if (op0 == 0b111 && op1 != 0b00) {
    return true;
  }
  return false;
}

bool check_execute_state_changed(relo_ctx_t *ctx, addr_t insn_addr) {
  for (auto iter = ctx->execute_state_map.begin(); iter != ctx->execute_state_map.end(); ++iter) {
    addr_t execute_state_changed_pc = iter->first;
    auto state = iter->second;
    if (execute_state_changed_pc == insn_addr) {
      return true;
    }
  }
  return false;
}

static void ARMRelocateSingleInsn(relo_ctx_t *ctx, int32_t insn) {

  auto turbo_assembler_ = static_cast<TurboAssembler *>(ctx->curr_assembler);
#define _ turbo_assembler_->

  bool is_insn_relocated = false;

  // top level encoding
  uint32_t cond, op0, op1;
  cond = bits(insn, 28, 31);
  op0 = bits(insn, 25, 27);
  op1 = bit(insn, 4);
  // Load/Store Word, Unsigned byte (immediate, literal)
  if (cond != 0b1111 && op0 == 0b010) {
    uint32_t P, U, o2, W, o1, Rn, Rt, imm12;
    P = bit(insn, 24);
    U = bit(insn, 23);
    W = bit(insn, 21);
    imm12 = bits(insn, 0, 11);
    Rn = bits(insn, 16, 19);
    Rt = bits(insn, 12, 15);
    o1 = bit(insn, 20);
    o2 = bit(insn, 22);
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
      addr32_t dst_vmaddr = 0;
      if (U == 0b1)
        dst_vmaddr = relo_cur_src_vmaddr(ctx) + imm12;
      else
        dst_vmaddr = relo_cur_src_vmaddr(ctx) - imm12;
      Register regRt = Register::R(Rt);

      auto label = new RelocLabel(dst_vmaddr);
      _ AppendRelocLabelEntry(label);

      // ===
      if (regRt.code() == pc.code()) {
        _ Ldr(VOLATILE_REGISTER, label);
        _ ldr(regRt, MemOperand(VOLATILE_REGISTER));
      } else {
        _ Ldr(regRt, label);
        _ ldr(regRt, MemOperand(regRt));
      }
      // ===
      is_insn_relocated = true;
    } while (0);
  }

  // Data-processing and miscellaneous instructions
  if (cond != 0b1111 && (op0 & 0b110) == 0b000) {
    uint32_t op0, op1, op2, op3, op4;
    op0 = bit(insn, 25);
    // Data-processing immediate
    if (op0 == 1) {
      uint32_t op0, op1;
      op0 = bits(insn, 23, 24);
      op1 = bits(insn, 20, 21);
      // Integer Data Processing (two register and immediate)
      if ((op0 & 0b10) == 0b00) {
        uint32_t opc, S, Rn;
        opc = bits(insn, 21, 23);
        S = bit(insn, 20);
        Rn = bits(insn, 16, 19);
        do {
          uint32_t dst_vmaddr;
          int Rd = bits(insn, 12, 15);
          int imm12 = bits(insn, 0, 11);
          int label = imm12;
          if (opc == 0b010 && S == 0b0 && Rn == 0b1111) {
            // ADR - A2 variant
            // add = FALSE
            dst_vmaddr = relo_cur_src_vmaddr(ctx) - imm12;
          } else if (opc == 0b100 && S == 0b0 && Rn == 0b1111) {
            // ADR - A1 variant
            // add = TRUE
            dst_vmaddr = relo_cur_src_vmaddr(ctx) + imm12;
          } else
            break;

          Register regRd = Register::R(Rd);
          RelocLabel *pseudoDataLabel = new RelocLabel(dst_vmaddr);
          _ AppendRelocLabelEntry(pseudoDataLabel);
          // ===
          _ Ldr(regRd, pseudoDataLabel);
          // ===
          is_insn_relocated = true;
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
    cond = bits(insn, 28, 31);
    op0 = bit(insn, 25);
    // Branch (immediate)
    if (op0 == 1) {
      uint32_t cond = 0, H = 0, imm24 = 0;
      bool flag_link;
      do {
        int imm24 = bits(insn, 0, 23);
        int label = imm24 << 2;
        uint32_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + label;
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
        // just modify orin insnuction label bits, and keep the link and cond bits, the next insnuction `b_imm` will
        // do the rest work.
        label = 0x4;
        imm24 = label >> 2;
        _ EmitARMInst((insn & 0xff000000) | imm24);
        if (flag_link) {
          _ bl(0);
          _ b(4);
        } else {
          _ b(4);
        }
        _ ldr(pc, MemOperand(pc, -4));
        _ EmitAddress(dst_vmaddr);
        is_insn_relocated = true;
      } while (0);
    }
  }

  // if the insn do not needed relocate, just rewrite the origin
  if (!is_insn_relocated) {
    _ EmitARMInst(insn);
  }
}

// relocate thumb-1 instructions
static void Thumb1RelocateSingleInsn(relo_ctx_t *ctx, int16_t insn) {
  auto turbo_assembler_ = static_cast<ThumbTurboAssembler *>(ctx->curr_assembler);
#define _ turbo_assembler_->

  bool is_insn_relocated = false;

  _ AlignThumbNop();

  uint32_t op = 0, rt = 0, rm = 0, rn = 0, rd = 0, shift = 0, cond = 0;
  int32_t offset = 0;

  int32_t op0 = 0, op1 = 0;
  op0 = bits(insn, 10, 15);
  // [Special data instructions and branch and exchange]
  if (op0 == 0b010001) {
    op0 = bits(insn, 8, 9);
    // [Add, subtract, compare, move (two high registers)]
    if (op0 != 0b11) {
      int rs = bits(insn, 3, 6);
      // rs is PC register
      if (rs == 15) {
        vmaddr_t curr_pc = relo_cur_src_vmaddr(ctx);

        uint16_t rewrite_inst = 0;
        rewrite_inst = (insn & 0xff87) | LeftShift((VOLATILE_REGISTER.code()), 4, 3);

        auto label = new ThumbRelocLabelEntry(curr_pc, false);
        _ AppendRelocLabelEntry(label);

        _ T2_Ldr(VOLATILE_REGISTER, label);
        _ EmitInt16(rewrite_inst);

        is_insn_relocated = true;
      }
    }

    // Branch and exchange
    if (op0 == 0b11) {
      int32_t L = bit(insn, 7);
      // BX
      if (L == 0b0) {
        rm = bits(insn, 3, 6);
        if (rm == pc.code()) {
          vmaddr_t dst_vmaddr = relo_cur_src_vmaddr(ctx);
          auto label = new ThumbRelocLabelEntry(dst_vmaddr, true);
          _ AppendRelocLabelEntry(label);

          _ T2_Ldr(pc, label);

          ctx->execute_state_map[dst_vmaddr] = ARMExecuteState;

          is_insn_relocated = true;
        }
      }
      // BLX
      if (L == 0b1) {
        if (rm == pc.code()) {
          vmaddr_t dst_vmaddr = relo_cur_src_vmaddr(ctx);
          auto label = new ThumbRelocLabelEntry(dst_vmaddr, true);
          _ AppendRelocLabelEntry(label);

          int label_branch_off = 4, label_continue_off = 4;
          _ t2_bl(label_branch_off);
          _ t2_b(label_continue_off);
          // Label: branch
          _ T2_Ldr(pc, label);
          // Label: continue

          ctx->execute_state_map[dst_vmaddr] = ARMExecuteState;

          is_insn_relocated = true;
        }
      }
    }
  }

  // ldr literal
  if ((insn & 0xf800) == 0x4800) {
    int32_t imm8 = bits(insn, 0, 7);
    int32_t offset = imm8 << 2;
    vmaddr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;
    dst_vmaddr = ALIGN_FLOOR(dst_vmaddr, 4);
    rt = bits(insn, 8, 10);

    auto label = new ThumbRelocLabelEntry(dst_vmaddr, false);
    _ AppendRelocLabelEntry(label);

    _ T2_Ldr(Register::R(rt), label);
    _ t2_ldr(Register::R(rt), MemOperand(Register::R(rt), 0));

    is_insn_relocated = true;
  }

  // adr
  if ((insn & 0xf800) == 0xa000) {
    rd = bits(insn, 8, 10);
    uint16_t offset = bits(insn, 0, 7);
    vmaddr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;

    auto label = new ThumbRelocLabelEntry(dst_vmaddr, false);
    _ AppendRelocLabelEntry(label);

    _ T2_Ldr(Register::R(rd), label);

    if (rd == pc.code())
      dst_vmaddr += 1;
    is_insn_relocated = true;
  }

  // b
  if ((insn & 0xf000) == 0xd000) {
    uint16_t cond = bits(insn, 8, 11);
    // cond != 111x
    if (cond >= 0b1110) {
      UNREACHABLE();
    }
    uint16_t imm8 = bits(insn, 0, 7);
    uint32_t offset = imm8 << 1;
    vmaddr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;

    auto label = new ThumbRelocLabelEntry(dst_vmaddr + 1, true);
    _ AppendRelocLabelEntry(label);

    // modify imm8 field
    imm8 = 0x4 >> 1;

    _ EmitInt16((insn & 0xfff0) | imm8);
    _ t1_nop(); // align
    _ t2_b(4);
    _ T2_Ldr(pc, label);

    is_insn_relocated = true;
  }

  // compare branch (cbz, cbnz)
  if ((insn & 0xf500) == 0xb100) {
    uint16_t imm5 = bits(insn, 3, 7);
    uint16_t i = bit(insn, 9);
    uint32_t offset = (i << 6) | (imm5 << 1);
    vmaddr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;
    rn = bits(insn, 0, 2);

    auto label = new ThumbRelocLabelEntry(dst_vmaddr + 1, true);
    _ AppendRelocLabelEntry(label);

    imm5 = bits(0x4 >> 1, 1, 5);
    i = bit(0x4 >> 1, 6);

    _ EmitInt16((insn & 0xfd07) | imm5 << 3 | i << 9);
    _ t1_nop(); // manual align
    _ t2_b(0);
    _ T2_Ldr(pc, label);

    is_insn_relocated = true;
  }

  // unconditional branch
  if ((insn & 0xf800) == 0xe000) {
    uint16_t imm11 = bits(insn, 0, 10);
    uint32_t offset = imm11 << 1;
    vmaddr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;

    auto label = new ThumbRelocLabelEntry(dst_vmaddr + 1, true);
    _ AppendRelocLabelEntry(label);

    _ T2_Ldr(pc, label);

    is_insn_relocated = true;
  }

  // if the insn do not needed relocate, just rewrite the origin
  if (!is_insn_relocated) {
#if 0
        if (relo_cur_src_vmaddr(ctx) % Thumb2_INST_LEN)
            _ t1_nop();
#endif
    _ EmitInt16(insn);
  }
}

static void Thumb2RelocateSingleInsn(relo_ctx_t *ctx, thumb1_inst_t insn1, thumb1_inst_t insn2) {
  auto turbo_assembler_ = static_cast<ThumbTurboAssembler *>(ctx->curr_assembler);
#define _ turbo_assembler_->

  bool is_insn_relocated = false;

  // if (turbo_assembler->pc_offset() % 4) {
  //   _ t1_nop();
  // }

  _ AlignThumbNop();

  // Branches and miscellaneous control
  if ((insn1 & 0xf800) == 0xf000 && (insn2 & 0x8000) == 0x8000) {
    uint32_t op1 = 0, op3 = 0;
    op1 = bits(insn1, 6, 9);
    op3 = bits(insn2, 12, 14);

    // B-T3 AKA b.cond
    if (((op1 & 0b1110) != 0b1110) && ((op3 & 0b101) == 0b000)) {

      int S = sbits(insn1, 10, 10);
      int J1 = bit(insn2, 13);
      int J2 = bit(insn2, 11);
      int imm6 = bits(insn1, 0, 5);
      int imm11 = bits(insn2, 0, 10);

      int32_t offset = (S << 20) | (J2 << 19) | (J1 << 18) | (imm6 << 12) | (imm11 << 1);
      vmaddr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;

      imm11 = 0x4 >> 1;
      _ EmitInt16(insn1 & 0xffc0);           // clear imm6
      _ EmitInt16((insn2 & 0xd000) | imm11); // 1. clear J1, J2, origin_imm12 2. set new imm11

      _ t2_b(4);
      _ t2_ldr(pc, MemOperand(pc, 0));
      _ EmitAddress(dst_vmaddr + THUMB_ADDRESS_FLAG);

      is_insn_relocated = true;
    }

    // B-T4 AKA b.w
    if ((op3 & 0b101) == 0b001) {
      int S = bit(insn1, 10);
      int J1 = bit(insn2, 13);
      int J2 = bit(insn2, 11);
      int imm10 = bits(insn1, 0, 9);
      int imm11 = bits(insn2, 0, 10);
      int i1 = !(J1 ^ S);
      int i2 = !(J2 ^ S);

      int32_t offset = (-S << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
      vmaddr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;

      _ t2_ldr(pc, MemOperand(pc, 0));
      _ EmitAddress(dst_vmaddr + THUMB_ADDRESS_FLAG);

      is_insn_relocated = true;
    }

    // BL, BLX (immediate) - T1 variant AKA bl
    if ((op3 & 0b101) == 0b101) {
      int S = bit(insn1, 10);
      int J1 = bit(insn2, 13);
      int J2 = bit(insn2, 11);
      int i1 = !(J1 ^ S);
      int i2 = !(J2 ^ S);
      int imm11 = bits(insn2, 0, 10);
      int imm10 = bits(insn1, 0, 9);
      // S is sign-bit, '-S' maybe not better
      int32_t offset = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (-S << 24);
      vmaddr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;

      _ t2_bl(4);
      _ t2_b(8);
      _ t2_ldr(pc, MemOperand(pc, 0));
      _ EmitAddress(dst_vmaddr + THUMB_ADDRESS_FLAG);

      is_insn_relocated = true;
    }

    // BL, BLX (immediate) - T2 variant AKA blx
    if ((op3 & 0b101) == 0b100) {
      int S = bit(insn1, 10);
      int J1 = bit(insn2, 13);
      int J2 = bit(insn2, 11);
      int i1 = !(J1 ^ S);
      int i2 = !(J2 ^ S);
      int imm10h = bits(insn1, 0, 9);
      int imm10l = bits(insn2, 1, 10);
      // S is sign-bit, '-S' maybe not better
      int32_t offset = (imm10l << 2) | (imm10h << 12) | (i2 << 22) | (i1 << 23) | (-S << 24);
      vmaddr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;
      dst_vmaddr = ALIGN(dst_vmaddr, 4);

      _ t2_bl(4);
      _ t2_b(8);
      _ t2_ldr(pc, MemOperand(pc, 0));
      _ EmitAddress(dst_vmaddr);

      is_insn_relocated = true;
    }
  }

  // Data-processing (plain binary immediate)
  if ((insn1 & (0xfa10)) == 0xf200 & (insn2 & 0x8000) == 0) {
    uint32_t op0 = 0, op1 = 0;
    op0 = bit(insn1, 8);
    op1 = bits(insn2, 5, 6);

    // Data-processing (simple immediate)
    if (op0 == 0 && (op1 & 0b10) == 0b00) {
      int o1 = bit(insn1, 7);
      int o2 = bit(insn1, 5);
      int rn = bits(insn1, 0, 3);

      // ADR
      if (((o1 == 0 && o2 == 0) || (o1 == 1 && o2 == 1)) && rn == 0b1111) {
        uint32_t i = bit(insn1, 10);
        uint32_t imm3 = bits(insn2, 12, 14);
        uint32_t imm8 = bits(insn2, 0, 7);
        uint32_t rd = bits(insn2, 8, 11);
        int32_t offset = imm8 | (imm3 << 8) | (i << 11);

        vmaddr_t dst_vmaddr = 0;
        if (o1 == 0 && o2 == 0) { // ADR - T3
          // ADR - T3 variant
          // adr with add
          dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;
        } else if (o1 == 1 && o2 == 1) { // ADR - T2
          // ADR - T2 variant
          // adr with sub
          dst_vmaddr = relo_cur_src_vmaddr(ctx) - offset;
        } else {
          UNREACHABLE();
        }

        _ t2_ldr(Register::R(rd), MemOperand(pc, 4));
        _ t2_b(0);
        _ EmitAddress(dst_vmaddr);

        is_insn_relocated = true;
      }
    }
  }

  // LDR literal (T2)
  if ((insn1 & 0xff7f) == 0xf85f) {
    uint32_t U = bit(insn1, 7);
    uint32_t imm12 = bits(insn2, 0, 11);
    uint16_t rt = bits(insn2, 12, 15);

    int32_t offset = imm12;
    vmaddr_t dst_vmaddr = 0;
    if (U == 1) {
      dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;
    } else {
      dst_vmaddr = relo_cur_src_vmaddr(ctx) - offset;
    }

    dst_vmaddr = ALIGN_FLOOR(dst_vmaddr, 4);

    Register regRt = Register::R(rt);

    _ t2_ldr(regRt, MemOperand(pc, 4));
    _ t2_b(4);
    _ EmitAddress(dst_vmaddr);
    _ t2_ldr(regRt, MemOperand(regRt, 0));

    is_insn_relocated = true;
  }

  // if the insn not needed relocate, just rewrite the origin
  if (!is_insn_relocated) {
#if 0
    if (relo_cur_src_vmaddr(ctx) % Thumb2_INST_LEN)
      _ t1_nop();
#endif
    _ EmitInt16(insn1);
    _ EmitInt16(insn2);
  }
}

void gen_arm_relocate_code(relo_ctx_t *ctx) {

#undef _
#define _ turbo_assembler_->

  auto turbo_assembler_ = static_cast<TurboAssembler *>(ctx->curr_assembler);
#define _ turbo_assembler_->

  auto relocated_buffer = turbo_assembler_->GetCodeBuffer();

  DLOG(0, "[arm] Thumb relocate %d start >>>>>", ctx->buffer_size);

  while (ctx->buffer_cursor < ctx->buffer + ctx->buffer_size) {
    uint32_t orig_off = ctx->buffer_cursor - ctx->buffer;
    uint32_t relocated_off = relocated_buffer->GetBufferSize();
    ctx->relocated_offset_map[orig_off] = relocated_off;

    arm_inst_t insn = *(arm_inst_t *)ctx->buffer_cursor;

    int last_relo_offset = turbo_assembler_->GetCodeBuffer()->GetBufferSize();

    ARMRelocateSingleInsn(ctx, insn);
    DLOG(0, "[arm] Relocate arm insn: 0x%x", insn);

    // move to next insnuction
    ctx->buffer_cursor += ARM_INST_LEN;

    // execute state changed
    addr32_t next_insn_addr = relo_cur_src_vmaddr(ctx) - ARM_PC_OFFSET;
    if (check_execute_state_changed(ctx, next_insn_addr)) {
      break;
    }
  }

  bool is_relocate_interrupted = ctx->buffer_cursor < ctx->buffer + ctx->buffer_size;
  if (is_relocate_interrupted) {
    turbo_assembler_->SetExecuteState(ThumbExecuteState);
  }
}

void gen_thumb_relocate_code(relo_ctx_t *ctx) {
  int relocated_insn_count = 0;

  auto turbo_assembler_ = static_cast<ThumbTurboAssembler *>(ctx->curr_assembler);
#define _ turbo_assembler_->

  auto relocated_buffer = turbo_assembler_->GetCodeBuffer();

  DLOG(0, "[arm] Thumb relocate %d start >>>>>", ctx->buffer_size);

  while (ctx->buffer_cursor < ctx->buffer + ctx->buffer_size) {
    uint32_t orig_off = ctx->buffer_cursor - ctx->buffer;
    uint32_t relocated_off = relocated_buffer->GetBufferSize();
    ctx->relocated_offset_map[orig_off] = relocated_off;

    // align nop
    _ t1_nop();

    thumb2_inst_t insn = *(thumb2_inst_t *)ctx->buffer_cursor;

    int last_relo_offset = relocated_buffer->GetBufferSize();
    if (is_thumb2(insn)) {
      Thumb2RelocateSingleInsn(ctx, (uint16_t)insn, (uint16_t)(insn >> 16));
      DLOG(0, "[arm] Relocate thumb2 insn: 0x%x", insn);
    } else {
      Thumb1RelocateSingleInsn(ctx, (uint16_t)insn);
      DLOG(0, "[arm] Relocate thumb1 insn: 0x%x", (uint16_t)insn);
    }

    // Move to next insnuction
    if (is_thumb2(insn)) {
      ctx->buffer_cursor += Thumb2_INST_LEN;
    } else {
      ctx->buffer_cursor += Thumb1_INST_LEN;
    }

    // execute state changed
    addr32_t next_insn_addr = relo_cur_src_vmaddr(ctx) - Thumb_PC_OFFSET;
    if (check_execute_state_changed(ctx, next_insn_addr)) {
      break;
    }
  }

  //  .thumb1 bx pc
  //  .thumb1 mov r8, r8
  //  .arm ldr pc, [pc, #-4]

  bool is_relocate_interrupted = ctx->buffer_cursor < ctx->buffer + ctx->buffer_size;
  if (is_relocate_interrupted) {
    turbo_assembler_->SetExecuteState(ARMExecuteState);
  }
}

void GenRelocateCodeAndBranch(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated) {
  relo_ctx_t ctx;
  ctx.buffer = ctx.buffer_cursor = (uint8_t *)buffer;
  ctx.buffer_size = origin->size;

  ctx.src_vmaddr = (vmaddr_t)origin->addr;
  ctx.dst_vmaddr = 0;

  auto *relocated_buffer = new CodeBuffer();
  ctx.relocated_buffer = relocated_buffer;

  ThumbTurboAssembler thumb_turbo_assembler_(0, ctx.relocated_buffer);
#define thumb_ thumb_turbo_assembler_.
  TurboAssembler arm_turbo_assembler_(0, ctx.relocated_buffer);
#define arm_ arm_turbo_assembler_.

  if (origin->addr % 2) {
    ctx.start_state = ThumbExecuteState;
    ctx.curr_state = ThumbExecuteState;
    ctx.curr_assembler = &thumb_turbo_assembler_;
    ctx.buffer -= THUMB_ADDRESS_FLAG;
  } else {
    ctx.start_state = ARMExecuteState;
    ctx.curr_state = ARMExecuteState;
    ctx.curr_assembler = &arm_turbo_assembler_;
  }

relocate_remain:
  if (ctx.curr_state == ThumbExecuteState) {
    ctx.curr_assembler = &thumb_turbo_assembler_;

    gen_thumb_relocate_code(&ctx);
    if (thumb_turbo_assembler_.GetExecuteState() == ARMExecuteState) {
      // translate interrupt as execute state changed
      bool is_translate_interrupted = ctx.buffer_cursor < ctx.buffer + ctx.buffer_size;
      if (is_translate_interrupted) {
        // add nop to align ARM
        if (thumb_turbo_assembler_.pc_offset() % 4)
          thumb_turbo_assembler_.t1_nop();
        goto relocate_remain;
      }
    }
  } else {
    ctx.curr_assembler = &arm_turbo_assembler_;

    gen_arm_relocate_code(&ctx);
    if (arm_turbo_assembler_.GetExecuteState() == ThumbExecuteState) {
      bool is_translate_interrupted = ctx.buffer_cursor < ctx.buffer + ctx.buffer_size;
      addr32_t origin_end = origin->addr + origin->size;
      // translate interrupt as execute state changed
      if (is_translate_interrupted) {

        goto relocate_remain;
      }
    }
  }

  // TODO: if last insn is unlink branch, skip
  addr32_t origin_code_end = (addr32_t)origin->addr + origin->size;
  addr32_t rest_insn_addr = origin_code_end;
  if (ctx.curr_state == ThumbExecuteState) {
    // branch to the rest of instructions
    thumb_ AlignThumbNop();
    thumb_ t2_ldr(pc, MemOperand(pc, 0));
    // Get the real branch address
    thumb_ EmitAddress(rest_insn_addr + THUMB_ADDRESS_FLAG);
  } else {
    // branch to the rest of instructions
    CodeGen codegen(&arm_turbo_assembler_);
    // Get the real branch address
    codegen.LiteralLdrBranch(rest_insn_addr);
  }

  // fixup the insn branch into trampoline(has been modified)
  arm_turbo_assembler_.RelocLabelFixup(&ctx.relocated_offset_map);

  thumb_turbo_assembler_.RelocLabelFixup(&ctx.relocated_offset_map);

  // realize all the Pseudo-Label-Data
  thumb_turbo_assembler_.RelocBind();

  // realize all the Pseudo-Label-Data
  arm_turbo_assembler_.RelocBind();

  // generate executable code
  {
    // assembler without specific memory address
    auto relocated_mem = MemoryAllocator::SharedAllocator()->allocateExecMemory(relocated_buffer->GetBufferSize());
    if (relocated_mem == nullptr)
      return;

    thumb_turbo_assembler_.SetRealizedAddress((void *)relocated_mem);
    arm_turbo_assembler_.SetRealizedAddress((void *)relocated_mem);

    AssemblyCode *code = NULL;
    code = AssemblyCodeBuilder::FinalizeFromTurboAssembler(ctx.curr_assembler);
    relocated->reset(code->addr, code->size);
  }

  // thumb
  if (ctx.start_state == ThumbExecuteState) {
    // add thumb address flag
    relocated->reset(relocated->addr, relocated->size);
  }

  // clean
  {
    thumb_turbo_assembler_.ClearCodeBuffer();
    arm_turbo_assembler_.ClearCodeBuffer();

    delete relocated_buffer;
  }
}

#endif
