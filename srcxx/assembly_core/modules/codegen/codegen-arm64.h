#ifndef ZZ_ARCH_ARM64_CODEGEN
#define ZZ_ARCH_ARM64_CODEGEN

#include "src/arch/arm64/assembler-arm64.h"

namespace zz {
namespace arm64 {
void GenerateRegisterSaveStub() {
  Assembler _assembler = Assembler();
#undef __
#define __ _assembler.
  __ stp(x0, x1, x2, 8);
}
} // namespace arm64
} // namespace zz

#endif