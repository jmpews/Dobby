
#include "core/modules/assembler/assembler-arm64.h"
#include "core/modules/codegen/codegen-arm64.h"

using namespace zz::arm64;

CodeBuffer *GenTrampoline(void *from, void *to) {

  TurboAssembler turbo_assembler_(from);
#define _ turbo_assembler_.

  CodeGen codegen(&turbo_assembler_);
  codegen.LiteralLdrBranch((uint64_t)to);

  return turbo_assembler_.GetCodeBuffer();
}