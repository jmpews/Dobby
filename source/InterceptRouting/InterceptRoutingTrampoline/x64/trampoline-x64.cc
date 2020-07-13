#include "dobby_internal.h"

#include "core/modules/assembler/assembler-x64.h"
#include "core/modules/codegen/codegen-x64.h"

#include "InstructionRelocation/x64/X64InstructionRelocation.h"

#include "InterceptRouting/ExtraInternalPlugin/NearBranchTrampoline/NearExecutableMemoryArena.h"
#include "InterceptRouting/ExtraInternalPlugin/RegisterPlugin.h"

using namespace zz::x64;

#define X64_ ((1 << 25) << 2) // signed

CodeBufferBase* GenerateNormalTrampolineBuffer(addr_t from, addr_t to) {
  CodeBufferBase *result = NULL;

  DLOG("Generate trampoline => %p", to);

  TurboAssembler turbo_assembler_((void *)from);
#define _ turbo_assembler_.

  CodeGen codegen(&turbo_assembler_);
  codegen.JmpBranch((uint64_t)to);

  result = turbo_assembler_.GetCodeBuffer()->copy();
  return result;
}