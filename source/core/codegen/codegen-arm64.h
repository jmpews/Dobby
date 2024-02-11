#pragma once

#include "core/codegen/codegen.h"
#include "core/assembler/assembler.h"
#include "core/assembler/assembler-arm64.h"

namespace zz {
namespace arm64 {

struct CodeGen : CodeGenBase {
  CodeGen(TurboAssembler *turbo_assembler) : CodeGenBase(turbo_assembler) {
  }
  void LiteralLdrBranch(uint64_t address) {
    auto turbo_assembler_ = reinterpret_cast<TurboAssembler *>(this->assembler_);
#undef _
#define _ turbo_assembler_-> // NOLINT: clang-tidy

    auto label = _ createDataLabel(address);
    _ Ldr(TMP_REG_0, label);
    _ br(TMP_REG_0);
  }
};

} // namespace arm64
} // namespace zz