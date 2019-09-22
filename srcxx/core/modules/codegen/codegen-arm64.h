#ifndef ZZ_MODULES_CODEGEN_CODEGEN_ARM64_H_
#define ZZ_MODULES_CODEGEN_CODEGEN_ARM64_H_

#include "core/modules/codegen/codegen.h"
#include "core/modules/assembler/assembler.h"
#include "core/modules/assembler/assembler-arm64.h"

namespace zz {
namespace arm64 {

class CodeGen : public CodeGenBase {
public:
  CodeGen(TurboAssembler *turbo_assember) : CodeGenBase(turbo_assember) {
  }
  void LiteralLdrBranch(uint64_t address);
};

} // namespace arm64
} // namespace zz

#endif