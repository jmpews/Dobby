#include "dobby_internal.h"

#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "InterceptRouting/x64/X64InterceptRouting.h"

#include "InstructionRelocation/x64/X64InstructionRelocation.h"

#include "core/modules/assembler/assembler-x64.h"
#include "core/modules/codegen/codegen-x64.h"

#include "ExtraInternalPlugin/RegisterPlugin.h"

#include "ExtraInternalPlugin/NearBranchTrampoline/JmpImmediate32/X64/JmpImm32Trampoline.h"

#include "ExtraInternalPlugin/NearBranchTrampoline/PlatformUtil/GetProcessMemoryLayout.h"

#include "ExtraInternalPlugin/NearBranchTrampoline/SearchCodeChunk.h"

using namespace zz::x64;

#define X64_JMP_IMM32_INST_SIZE 5
#define X64_JMP_IMM32_RANGE_SIZE (1UL << 32)

// If BranchType is B_Branch and the branch_range of `B` is not enough, build the transfer to forward the b branch, if
static AssemblyCode *BuildFastForwardTrampoline(uintptr_t forward_address) {
  TurboAssembler turbo_assembler_;
  CodeGen codegen(&turbo_assembler_);
  void *fast_forward_trampoline = NULL;
  AssemblyCodeChunk *codeChunk;

  codegen.JmpBranch((addr_t)forward_address);

  // Patch
  MemoryOperationError err;
  err = CodePatchTool::PatchCodeBuffer(codeChunk->address,
                                       reinterpret_cast<CodeBufferBase *>(turbo_assembler_.GetCodeBuffer()));
  CHECK_EQ(err, kMemoryOperationSuccess);
  AssemblyCode *code =
      AssemblyCode::FinalizeFromAddress((uintptr_t)codeChunk->address, turbo_assembler_.GetCodeBuffer()->getSize());

  return code;
}

bool JmpImm32Routing::Prepare(InterceptRouting *routing) {
  X64InterceptRouting *routing_arm64 = reinterpret_cast<X64InterceptRouting *>(routing);
  HookEntry *entry                   = routing->GetHookEntry();
  addr_t search_start;
  addr_t search_end;
  if ((addr_t)entry->target_address < (addr_t)X64_JMP_IMM32_RANGE_SIZE)
    search_start = 0;
  else
    search_start = (addr_t)entry->target_address - X64_JMP_IMM32_RANGE_SIZE;
  if ((addr_t)-1 - (addr_t)entry->target_address < X64_JMP_IMM32_RANGE_SIZE)
    search_end = (addr_t)-1;
  else
    search_end = (addr_t)entry->target_address + X64_JMP_IMM32_RANGE_SIZE;

  AssemblyCodeChunk *codeChunk = SearchCodeChunk(search_start, search_end, X64_JMP_IMM32_INST_SIZE);
  return true;
}

bool JmpImm32Routing::Active(InterceptRouting *routing) {
  X64InterceptRouting *routing_arm64 = reinterpret_cast<X64InterceptRouting *>(routing);
  HookEntry *entry                   = routing->GetHookEntry();
  uint64_t target_address            = (uint64_t)entry->target_address;

  AssemblyCode *fast_forward_trampoline;

  fast_forward_trampoline = BuildFastForwardTrampoline((uintptr_t)routing->GetTrampolineTarget());

  TurboAssembler turbo_assembler_;
#define _ turbo_assembler_.
  _ jmp(Immediate((addr_t)fast_forward_trampoline->raw_instruction_start() - (addr_t)target_address));

  MemoryOperationError err;
  err = CodePatchTool::PatchCodeBuffer((void *)target_address,
                                       reinterpret_cast<CodeBufferBase *>(turbo_assembler_.GetCodeBuffer()));
  CHECK_EQ(err, kMemoryOperationSuccess);
  AssemblyCode::FinalizeFromAddress(target_address, turbo_assembler_.GetCodeBuffer()->getSize());
  return true;
}
