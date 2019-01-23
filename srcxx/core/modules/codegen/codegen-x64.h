#ifndef ZZ_MODULES_CODEGEN_CODEGEN_X64_H_
#define ZZ_MODULES_CODEGEN_CODEGEN_X64_H_

#include "core/modules/codegen/codegen.h"
#include "core/modules/assembler/assembler.h"
#include "core/modules/assembler/assembler-x64.h"

namespace zz {
namespace x64 {

class CodeGen : public CodeGenBase {
public:
  CodeGen(TurboAssembler *turbo_assember) : CodeGenBase(turbo_assember) {
  }
};

} // namespace arm64
} // namespace zz

#endif