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
  Label() : location_(kLocationUnbound) {
  }
  ~Label() {
  }
}

class Assembler {
private:
  CodeBuffer *buffer_;

public:
  void b(int64_t imm);

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
  }

  void EmitLoadStoreReg(LoadStoreRegOp op, Register rt, Address a, OperandSize sz) {
    const int32_t size     = Log2OperandSizeBytes(sz);
    const int32_t encoding = op | ((size & 0x3) << kSzShift) | Arm64Encode::Rt(rt) | a.encoding();
    Emit(encoding);
  }

  void Assembler::BranchLink(const StubEntry &stub_entry, Patchability patchable) {
    const Code &target   = Code::ZoneHandle(stub_entry.code());
    const int32_t offset = ObjectPool::element_offset(object_pool_wrapper_.FindObject(target, patchable));
    LoadWordFromPoolOffset(CODE_REG, offset);
    ldr(TMP, FieldAddress(CODE_REG, Code::entry_point_offset()));
    blr(TMP);
  }
};

} // namespace arm64
} // namespace zz

#endif