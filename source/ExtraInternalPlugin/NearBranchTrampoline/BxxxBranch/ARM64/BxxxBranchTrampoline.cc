#include "dobby_internal.h"

#include "./BxxxBranchTrampoline.h"

#include "ExecMemory/ExecutableMemoryArena.h"

#include "PlatformInterface/ExecMemory/CodePatchTool.h"

#include "InstructionRelocation/arm64/ARM64InstructionRelocation.h"

#include "core/arch/arm64/registers-arm64.h"
#include "core/modules/assembler/assembler-arm64.h"
#include "core/modules/codegen/codegen-arm64.h"

#include "ExtraInternalPlugin/NearBranchTrampoline/NearExecutableMemoryArena.h"
#include "ExtraInternalPlugin/RegisterPlugin.h"

#define ARM64_TINY_REDIRECT_SIZE 4
#define ARM64_B_XXX_RANGE (1 << 25) // signed

#define ARM64InterceptRouting InterceptRouting

using namespace zz;
using namespace zz::arm64;

void dobby_enable_arm64_bxx_branch_trampoline() {
  ExtraInternalPlugin::registerPlugin("arm64_bxx_trampoline", new BxxxRouting);
}

// If BranchType is B_Branch and the branch_range of `B` is not enough, build the transfer to forward the b branch, if
static AssemblyCode *BuildFastForwardTrampoline(addr_t source_address, addr_t forward_address) {
  AssemblyCodeChunk *codeChunk = NearExecutableMemoryArena::AllocateCodeChunk(
      ARM64_TINY_REDIRECT_SIZE, (uintptr_t)source_address, ARM64_B_XXX_RANGE);

  TurboAssembler turbo_assembler_(codeChunk->address);
  CodeGen codegen(&turbo_assembler_);
  codegen.LiteralLdrBranch(forward_address);

  AssemblyCode *code = AssemblyCode::FinalizeFromTurboAssember(&turbo_assembler_);
  return code;
}

bool BxxxRouting::Active(InterceptRouting *routing) {
  ARM64InterceptRouting *routing_arm64 = reinterpret_cast<ARM64InterceptRouting *>(routing);
  HookEntry *entry                     = routing->GetHookEntry();
  addr_t source_address                = (addr_t)entry->target_address;

  addr_t trampoline_target_address = (addr_t)routing_arm64->GetTrampolineTarget();

  TurboAssembler turbo_assembler_((void *)source_address);
#define _ turbo_assembler_.

  // branch to trampoline_target directly
  if (llabs((long long)trampoline_target_address - (long long)source_address) < ARM64_B_XXX_RANGE) {
    _ b(trampoline_target_address - source_address);
  } else {
    AssemblyCode *fast_forward_trampoline;
    fast_forward_trampoline = BuildFastForwardTrampoline(source_address, trampoline_target_address);
    _ b(fast_forward_trampoline->raw_instruction_start() - source_address);
  }

  AssemblyCode *code = AssemblyCode::FinalizeFromTurboAssember(&turbo_assembler_);

  return true;
}
