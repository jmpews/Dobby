#include "vm_core/modules/codegen/codegen-arm64.h"

namespace zz {
namespace arm64 {

void CodeGen::LiteralBrBranch(uint64_t address) {
  TurboAssembler *turbo_assembler_ = reinterpret_cast<TurboAssembler *>(this->assembler_);
#define _ turbo_assembler_->
  PseudoLabel address_ptr;
  _ Ldr(Register::X(17), &address_ptr);
  _ br(Register::X(17));
  _ PseudoBind(&address_ptr);
  _ EmitInt64(address);
}

} // namespace arm64
} // namespace zz
