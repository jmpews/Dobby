#ifndef ZZ_ARCHITECTURE_ARCH_ARM64_ASSEMBLER_H_
#define ZZ_ARCHITECTURE_ARCH_ARM64_ASSEMBLER_H_

#include "vm_core/arch/arm64/constants-arm64.h"
#include "vm_core/arch/arm64/instructions-arm64.h"
#include "vm_core/arch/arm64/registers-arm64.h"

#include "vm_core/modules/assembler/assembler.h"

#include "vm_core/macros.h"
#include "vm_core/base/code-buffer.h"
#include "vm_core/utils.h"

namespace zz {
namespace arm64 {


class PseudoLabel : public Label {
  enum PseudoLabelType { kLdrPseudoLabel };

  typedef struct _PseudoLabelInstruction {
    int position_;
    PseudoLabelType type_;
  } PseudoLabelInstruction;

public:
  bool has_confused_instructions() {
    return instructions_.size() > 0;
  }
  void link_confused_instructions(CodeBuffer *buffer = nullptr) {
    if (buffer)
      buffer_ = buffer;

    int32_t offset       = instruction->position_ - this->position_;
    const int32_t inst32 = buffer_.Load32(instruction->position);
    for (auto instruction : instructions_) {
      switch (instruction.type_) {
      case kLdrPseudoLabel: {
        const int32_t encoded = (inst32 & 0xfff) | offset;
      } break;
      default:
        break;
      }
      buffer_.Store32(instrcution->position, encoed);
    }
  };

private:
  // From a design perspective, these fix-function write as callback, maybe beeter.
  void FixLdr(PseudoLabelInstruction *instruction){
      // dummy
  };

private:
  CodeBuffer *buffer_;
  std::vector<PseudoLabelInstruction> instructions_;
};

class Assembler : public AssemblerBase {

public:
  Assembler();

  void FlushICache();

  void Emit(int32_t value);

  void EmitInt64(int64_t value);

  void Bind(Label *label);

  void b(int64_t imm) {
    int32_t imm26 = imm >> 2;
  }

  void b(Label *label) {
    int offset = LinkAndGetByteOffsetTo(label);
    b(offset);
  }

  int LinkAndGetByteOffsetTo(Label *label);

  void ldr_literal(Register rt, int64_t imm) {
    LoadRegLiteralOp op;
    switch (rt.type()) {
    case CPURegister::Register_32:
      op = OPT_W(LDR, literal);
      break;
    case CPURegister::Register_X:
      op = OPT_X(LDR, literal);
      break;
    case CPURegister::SIMD_FP_Register_S:
      op = OPT_S(LDR, literal);
      break;
    case CPURegister::SIMD_FP_Register_D:
      op = OPT_D(LDR, literal);
      break;
    case CPURegister::SIMD_FP_Register_Q:
      op = OPT_Q(LDR, literal);
      break;
    default:
      break;
    }
    EmitLoadRegLiteral(op, rt, imm);
  }

  void ldr(Register rt, Register rn, int64_t imm) {
    LoadStoreUnscaledOffsetOp op = OP_X(LDR);
    EmitLoadStoreReg(op, rt, rn, imm);
  }

  // Move and keep.
  void movk(const Register &rd, uint64_t imm, int shift = -1) {
    MoveWide(rd, imm, shift, MOVK);
  }

  // Move with non-zero.
  void movn(const Register &rd, uint64_t imm, int shift = -1) {
    MoveWide(rd, imm, shift, MOVN);
  }

  // Move with zero.
  void movz(const Register &rd, uint64_t imm, int shift = -1) {
    MoveWide(rd, imm, shift, MOVZ);
  }

  void ldp(const Register &rt, const Register &rt2, const Register &rn, int64_t imm) {
    EmitLoadStorePair(OPT_X(LDP, pair), rt, rt2, rn, imm);
  }

  void stp(const Register &rt, const Register &rt2, const Register &rn, int64_t imm) {
    EmitLoadStorePair(OPT_X(STP, pair), rt, rt2, rn, imm);
  }

private:
  void EmitLoadRegLiteral(LoadRegLiteralOp op, CPURegister rt, int64_t imm) {
    const int32_t encoding = op | LFT(imm, 26, 5) | Rt(rt);
    Emit(encoding);
  }

  void EmitLoadStoreReg(LoadStoreUnscaledOffsetOp op, CPURegister rt, CPURegister rn, int64_t imm) {
    assert(imm > 0);
    int64_t imm12          = imm;
    const int32_t encoding = op | LFT(imm12, 12, 10) | Rt(rn) | Rt(rt);
    Emit(encoding);
  }

  void MoveWide(Register rd, uint64_t imm, int shift, MoveWideImmediateOp mov_op) {
    assert(shift >= 0);
    shift /= 16;

    XCHECK(imm <= 0xffff);

    int32_t op    = MoveWideImmediateFixed | mov_op;
    int32_t imm16 = LFT(imm, 16, 5);
    Emit(op | sf(rd) | hw(shift) | imm16 | Rd(rd));
  }

  void EmitLoadStorePair(LoadStorePairOffsetOp op, CPURegister rt, CPURegister rt2, CPURegister rn, int64_t imm) {
    int scale    = bits(op, 30, 31);
    int32_t imm7 = imm >> scale;
    Emit(op | imm7 | Rt2(rt2) | Rn(rn) | Rt(rt));
  }
};

class TurboAssembler : public Assembler {
private:
  // std::vector<PseudoLabel *> pseudo_labels;

public:
  TurboAssembler();

  void ldr(Register rt, PseudoLabel *label) {
    const int64_t dest = label->Position() - buffer_.Size();

    if (label->IsBound()) {
      ldr(rt, dest);
    } else {
      ldr(rt, label->Position());
      label->link_to(buffer_->Size());
    }
  }

  void pseudo_bind(PseudoLabel *label) {
    const uintptr_t bound_pc = buffer_.Size();
    // If some instructions have been wrote, before the label bound, we need link these `confused` instructions
    if (label->has_confused_instructions()) {
      label->link_confused_instructions();
    }
    label->bind_to(bound_pc);
  }

#if 0
  void pseudo_fix() {
    for (auto pseudo_label : pseudo_labels) {
      pseudo_label->Fix();
    }
  };
#endif

  void Mov(Register rd, uint64_t imm) {
    const uint32_t w0 = Utils::Low32Bits(imm);
    const uint32_t w1 = Utils::High32Bits(imm);
    const uint16_t h0 = Utils::Low16Bits(w0);
    const uint16_t h1 = Utils::High16Bits(w0);
    const uint16_t h2 = Utils::Low16Bits(w1);
    const uint16_t h3 = Utils::High16Bits(w1);
    movz(rd, h0, 0);
    movk(rd, h1, 16);
    movk(rd, 32);
    movk(rd, h3, 48);
  }

private:
};

} // namespace arm64
} // namespace zz

#endif