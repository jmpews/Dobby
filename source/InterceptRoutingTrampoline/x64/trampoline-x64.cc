#include "core/modules/assembler/assembler-x64.h"
#include "core/modules/codegen/codegen-x64.h"

#include "logging/check_logging.h"

using namespace zz::x64;

CodeBufferBase *GenTrampoline(void *from, void *to) {
  TurboAssembler turbo_assembler_(from);
#define _ turbo_assembler_.

  DCHECK_EQ(from, turbo_assembler_.GetRealizeAddress());
  turbo_assembler_.CommitRealizeAddress(from);

  CodeGen codegen(&turbo_assembler_);
  codegen.JmpBranch((addr_t)to);

  return turbo_assembler_.GetCodeBuffer()->copy();
}