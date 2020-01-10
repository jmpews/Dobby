#include "dobby_internal.h"

#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "intercept_routing_handler.h"

#include "InstructionRelocation/arm64/ARM64InstructionRelocation.h"

#include "core/modules/assembler/assembler-arm64.h"
#include "core/modules/codegen/codegen-arm64.h"

#include "ExtraInternalPlugin/NearBranchTrampoline/NearExecutableMemoryArena.h"
#include "ExtraInternalPlugin/BxxxBranchTrampoline/ARM64/BxxxBranchTrampoline.h"
#include "ExtraInternalPlugin/RegisterPlugin.h"

#define ARM64_TINY_REDIRECT_SIZE 4
#define ARM64_B_XXX_RANGE (1 << 25) // signed

using namespace zz::arm64;

void dobby_enable_arm64_bxx_branch_trampoline() {
  ExtraInternalPlugin::registerPlugin("arm64_bxx_trampoline", new BxxxRouting);
}

// If BranchType is B_Branch and the branch_range of `B` is not enough, build the transfer to forward the b branch, if
static AssemblyCode *BuildFastForwardTrampoline(uintptr_t forward_address) {
  TurboAssembler turbo_assembler_;
  CodeGen codegen(&turbo_assembler_);
  void *fast_forward_trampoline = NULL;

  AssemblyCodeChunk *codeChunk = NearExecutableMemoryArena::AllocateCodeChunk(
      ARM64_TINY_REDIRECT_SIZE, (uintptr_t)entry->target_address, ARM64_B_XXX_RANGE);

  codegen.LiteralLdrBranch(forward_address);

  { // patch
    MemoryOperationError err;
    err = CodePatchTool::PatchCodeBuffer(codeChunk->address,
                                         reinterpret_cast<CodeBufferBase *>(turbo_assembler_.GetCodeBuffer()));
    CHECK_EQ(err, kMemoryOperationSuccess);
  }

  AssemblyCode *code =
      AssemblyCode::FinalizeFromAddress((uintptr_t)codeChunk->address, turbo_assembler_.GetCodeBuffer()->getSize());

  turbo_assembler_.release();

  return code;
}

bool BxxxRouting::Active(InterceptRouting *routing) {
  ARM64InterceptRouting *routing_arm64 = reinterpret_cast<ARM64InterceptRouting *>(routing);
  HookEntry *entry                     = routing->GetHookEntry();
  addr_t source_address                = (addr_t)entry->target_address;

  addr_t trampoline_target_address = routing->GetTrampolineTarget();

  TurboAssembler turbo_assembler_(source_address);
#define _ turbo_assembler_.

  // branch to trampoline_target directly
  if (abs(trampoline_target_address - source_address) < ARM64_B_XXX_RANGE) {
    _ b(trampoline_target_address - source_address);
  } else {
    AssemblyCode *fast_forward_trampoline;
    fast_forward_trampoline = BuildFastForwardTrampoline();
    _ b(fast_forward_trampoline->raw_instruction_start() - source_address);
  }

  MemoryOperationError err;
  err = CodePatchTool::PatchCodeBuffer((void *)source_address,
                                       reinterpret_cast<CodeBufferBase *>(turbo_assembler_.GetCodeBuffer()));
  CHECK_EQ(err, kMemoryOperationSuccess);

  AssemblyCode::FinalizeFromAddress(source_address, turbo_assembler_.GetCodeBuffer()->getSize());

  turbo_assembler_.release();

  return true;
}
