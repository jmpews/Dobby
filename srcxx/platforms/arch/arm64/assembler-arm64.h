#ifndef ARCH_ARM64
#define ARCH_ARM64

#include "scrxx/globals.h"
#include "srcxx/platforms/code-buffer.h"

#include "srcxx/platforms/arch/instructions-arm64.h"
#include "srcxx/platforms/arch/registers-arm64.h"

namespace zz {
namespace arm64 {

class Label {
public:
  Label() : location_() {
  }
  ~Label() {
  }
}

class Assembler {
private:
  CodeBuffer *buffer_;

public:
  void b(int64_t imm) {
    // TODO: need `mask` check
    int32_t imm26 = imm >> 2;
    Emit(B | ImmUncondBranch(imm26));
  }

  void b(Label *label) {
  }

  void ldr_literal(Register rt, int64 imm) {
    LoadLiteralOp op;
    switch (rt->RegisterType()) {
    case Register_32:
      op = OPT_W(LDR, literal);
      break;
    case Register_X:
      op = OPT_X(LDR, literal);
      break;
    case SIMD_FP_Register_S:
      op = OPT_S(LDR, literal);
      break;
    case SIMD_FP_Register_D:
      op = OPT_D(LDR, literal);
      break;
    case SIMD_FP_Register_Q:
      op = OPT_Q(LDR, literal);
      break;
    default:
      break;
    }
    EmitLoadRegLiteral(op, rt, imm);
  }

  void EmitLoadRegLiteral(LoadRegLiteralOp op, CPURegister rt, int64 imm) {
    const int32_t encoding = op | LFT(imm, 5) | rt.index;
    Emit(encoding);
  }

  void ldr_reg_imm(Register rt, Register rn, int64 imm) {
    LoadStoreUnsignedOffset op = OPT_X(LDR, unsigned);
    EmitLoadStoreReg(op, rt, rn, imm);
  }

  void EmitLoadStoreReg(LoadStoreRegOp op, Register rt, Register rn, int64 imm) {
    assert(imm > 0);
    int64_t imm12          = imm;
    const int32_t encoding = op | LFT(imm12, 10) | LFT(rn.index, 5) | LFT(rt.index, 0);
    Emit(encoding);
  }
};

} // namespace arm64
} // namespace zz

#endif