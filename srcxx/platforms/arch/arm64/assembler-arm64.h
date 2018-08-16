#ifndef ARCH_ARM64
#define ARCH_ARM64

#include "srcxx/platforms/code-buffer.h"

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
  void b(int64_t imm26);
  void ldr();

  void EmitLoadStoreReg(LoadStoreRegOp op, Register rt, Address a, OperandSize sz) {
    const int32_t size     = Log2OperandSizeBytes(sz);
    const int32_t encoding = op | ((size & 0x3) << kSzShift) | Arm64Encode::Rt(rt) | a.encoding();
    Emit(encoding);
  }

  void EmitInst(uint32 inst);
};

} // namespace arm64
} // namespace zz

#endif