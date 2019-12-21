#ifndef CORE_CODEGEN_X64_H
#define CORE_CODEGEN_X64_H

#include "core/modules/codegen/codegen.h"
#include "core/modules/assembler/assembler.h"
#include "core/modules/assembler/assembler-x64.h"

namespace zz {
namespace x64 {

class CodeGen : public CodeGenBase {
public:
  CodeGen(TurboAssembler *turbo_assember) : CodeGenBase(turbo_assember) {
  }
  void JmpBranch(addr_t address);
};

} // namespace x64
} // namespace zz

#endif