#ifndef CORE_CODEGEN_ARM_H
#define CORE_CODEGEN_ARM_H

#include "core/modules/codegen/codegen.h"
#include "core/modules/assembler/assembler.h"
#include "core/modules/assembler/assembler-arm.h"

namespace zz {
namespace arm {

class CodeGen : public CodeGenBase {
public:
  CodeGen(TurboAssembler *turbo_assember) : CodeGenBase(turbo_assember) {
  }

  void LiteralLdrBranch(uint32_t address);
};

} // namespace arm
} // namespace zz

#endif