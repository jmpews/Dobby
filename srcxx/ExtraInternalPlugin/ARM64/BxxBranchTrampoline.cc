#include "hookzz_internal.h"

#include "ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "AssemblyClosureTrampoline.h"

#include "intercept_routing_handler.h"

#include "InterceptRouting/arm64/ARM64InterceptRouting.h"

#include "InstructionRelocation/arm64/ARM64InstructionRelocation.h"

#include "core/modules/assembler/assembler-arm64.h"
#include "core/modules/codegen/codegen-arm64.h"

#include "BxxBranchTrampoline.h"
#include "ExtraInternalPlugin/RegisterPlugin.h"

using namespace zz::arm64;

// If BranchType is B_Branch and the branch_range of `B` is not enough, build the transfer to forward the b branch, if
void BuildFastForwardTrampoline() {
  TurboAssembler turbo_assembler_;
  CodeGen codegen(&turbo_assembler_);
  uint64_t forward_address = 0;
  void *fast_forward_trampoline = NULL;
  AssemblyCodeChunk *codeChunk;

  codegen.LiteralLdrBranch(forward_address);

  // Patch
  MemoryOperationError err;
  err = CodePatchTool::PatchCodeBuffer(codeChunk->address, reinterpret_cast<CodeBufferBase *>(turbo_assembler_.GetCodeBuffer()));
  CHECK_EQ(err, kMemoryOperationSuccess);
  AssemblyCode*code = AssemblyCode::FinalizeFromAddress((uintptr_t)codeChunk->address, turbo_assembler_.GetCodeBuffer()->getSize());

  fast_forward_trampoline = (void *)code->raw_instruction_start();
}

void GenerateBxxTrampoline(InterceptRouting *routing) {
  HookEntry *entry = routing->GetHookEntry();
}
