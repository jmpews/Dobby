#include "core/modules/codegen/codegen-x64.h"

namespace zz {
namespace x64 {

void CodeGen::JmpBranch(addr_t address) {
  TurboAssembler *turbo_assembler_ = reinterpret_cast<TurboAssembler *>(this->assembler_);
#define _ turbo_assembler_->
  dword offset = address - turbo_assembler_->CurrentIP();
  _ jmp(Immediate(offset));
}

} // namespace x64
} // namespace zz
