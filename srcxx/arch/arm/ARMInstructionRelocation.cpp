#include "srcxx/arch/arm/ARMInstructionRelocation.h"
#include "srcxx/globals.h"

#include "vm_core/arch/arm/registers-arm.h"
#include "vm_core/modules/assembler/assembler-arm.h"

namespace zz {
namespace arm {

Code *GenRelocateCode(uintptr_t src_pc, int count) {
  uintptr_t cur_pc = src_pc;
  uint32_t inst    = *(uint32_t *)src_pc;
  int t            = 0;

  // Generate executable code
  AssemblerCode *code = AssemblerCode::FinalizeTurboAssembler(&turbo_assembler_);
  return code;
}

} // namespace arm
} // namespace zz
