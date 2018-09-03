#ifndef ZZ_MODULES_CODEGEN_CODEGEN_ARM64_H_
#define ZZ_MODULES_CODEGEN_CODEGEN_ARM64_H_

#include "vm_core/modules/codegen/codegen.h"
#include "vm_core/modules/assembler/assembler.h"
#include "vm_core/modules/assembler/assembler-arm64.h"

namespace zz {
namespace arm64 {

class CodeGen : public CodeGenBase {
public:
  CodeGen(TurboAssembler *turbo_assember) : CodeGenBase(turbo_assember) {
  }
  void LiteralBrBranch(uint64_t address);
};

} // namespace arm64
} // namespace zz

#endif