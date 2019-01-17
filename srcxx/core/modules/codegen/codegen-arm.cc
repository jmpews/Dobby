#include "core/modules/codegen/codegen-arm.h"

namespace zz {
namespace arm {

void CodeGen::LiteralLdrBranch(uint32_t address) {
  TurboAssembler *turbo_assembler_ = reinterpret_cast<TurboAssembler *>(this->assembler_);
  #define _ turbo_assembler_->
  _ ldr(pc, MemOperand(pc, -4));
  _ Emit((int32_t)address);
}

} // namespace arm
} // namespace zz
