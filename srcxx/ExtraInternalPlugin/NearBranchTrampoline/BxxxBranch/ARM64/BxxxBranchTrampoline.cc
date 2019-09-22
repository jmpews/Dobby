#include "hookzz_internal.h"

#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "intercept_routing_handler.h"

#include "InterceptRouting/arm64/ARM64InterceptRouting.h"

#include "InstructionRelocation/arm64/ARM64InstructionRelocation.h"

#include "core/modules/assembler/assembler-arm64.h"
#include "core/modules/codegen/codegen-arm64.h"

#include "ExtraInternalPlugin/BxxxBranchTrampoline/ARM64/BxxxBranchTrampoline.h"
#include "ExtraInternalPlugin/BxxxBranchTrampoline/ShellCodeCave/ShellCodeCave.h"
#include "ExtraInternalPlugin/RegisterPlugin.h"

#define ARM64_TINY_REDIRECT_SIZE 4
#define ARM64_B_XXX_RANGE (1 << 25) // signed

using namespace zz::arm64;

// If BranchType is B_Branch and the branch_range of `B` is not enough, build the transfer to forward the b branch, if
static AssemblyCode *BuildFastForwardTrampoline(uintptr_t forward_address) {
  TurboAssembler turbo_assembler_;
  CodeGen codegen(&turbo_assembler_);
  void *fast_forward_trampoline = NULL;
  AssemblyCodeChunk *codeChunk;

  codegen.LiteralLdrBranch(forward_address);

  // Patch
  MemoryOperationError err;
  err = CodePatchTool::PatchCodeBuffer(codeChunk->address,
                                       reinterpret_cast<CodeBufferBase *>(turbo_assembler_.GetCodeBuffer()));
  CHECK_EQ(err, kMemoryOperationSuccess);
  AssemblyCode *code =
      AssemblyCode::FinalizeFromAddress((uintptr_t)codeChunk->address, turbo_assembler_.GetCodeBuffer()->getSize());

  return code;
}

bool BxxxRouting::Prepare(InterceptRouting *routing) {
  ARM64InterceptRouting *routing_arm64 = reinterpret_cast<ARM64InterceptRouting *>(routing);
  HookEntry *entry                     = routing->GetHookEntry();

  AssemblyCodeChunk *codeChunk =
      SearchCodeCave(ARM64_TINY_REDIRECT_SIZE, (uintptr_t)entry->target_address, ARM64_B_XXX_RANGE);
  if (codeChunk) {
    routing_arm64->branch_type_ = ARM64InterceptRouting::ARM64_B_Branch;
  }
  return true;
}

bool BxxxRouting::Active(InterceptRouting *routing) {
  ARM64InterceptRouting *routing_arm64 = reinterpret_cast<ARM64InterceptRouting *>(routing);
  HookEntry *entry                     = routing->GetHookEntry();
  uint64_t target_address              = (uint64_t)entry->target_address;

  AssemblyCode *fast_forward_trampoline;

  fast_forward_trampoline = BuildFastForwardTrampoline((uintptr_t)routing->GetTrampolineTarget());

  TurboAssembler turbo_assembler_;
#define _ turbo_assembler_.
  _ b((int64_t)fast_forward_trampoline->raw_instruction_start() - (int64_t)target_address);

  MemoryOperationError err;
  err = CodePatchTool::PatchCodeBuffer((void *)target_address,
                                       reinterpret_cast<CodeBufferBase *>(turbo_assembler_.GetCodeBuffer()));
  CHECK_EQ(err, kMemoryOperationSuccess);
  AssemblyCode::FinalizeFromAddress(target_address, turbo_assembler_.GetCodeBuffer()->getSize());
  return true;
}
