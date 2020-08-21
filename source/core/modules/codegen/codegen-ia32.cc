#include "common/macros/platform_macro.h"
#if defined(TARGET_ARCH_IA32)

#include "core/modules/codegen/codegen-ia32.h"

namespace zz {
namespace x86 {

void CodeGen::JmpNearIndirect(uint32_t address) {
  TurboAssembler *turbo_assembler_ = reinterpret_cast<TurboAssembler *>(this->assembler_);
#define _ turbo_assembler_->
#define __ turbo_assembler_->GetCodeBuffer()->
  uint32_t currIP = turbo_assembler_->CurrentIP() + 6;
  dword offset = (dword)(address - currIP);

  // RIP-relative addressing
  __ Emit8(0xFF);
  __ Emit8(0x25);
  __ Emit32(offset);
}

} // namespace x86
} // namespace zz

#endif