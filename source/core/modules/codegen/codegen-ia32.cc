#include "core/modules/codegen/codegen-x64.h"

namespace zz {
namespace x64 {

void CodeGen::JmpBranch(addr_t address) {
  TurboAssembler *turbo_assembler_ = reinterpret_cast<TurboAssembler *>(this->assembler_);
#define _ turbo_assembler_->
#define __ turbo_assembler_->GetCodeBuffer()->
  dword offset = (dword)(address - turbo_assembler_->CurrentIP());

  // RIP-relative addressing
  __ Emit8(0xFF);
  __ Emit8(0x25);
  __ Emit32(0x0);
  __ Emit64(address);
}

} // namespace x64
} // namespace zz
