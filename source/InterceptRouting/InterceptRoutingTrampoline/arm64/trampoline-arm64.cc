#include "common/macros/platform_macro.h"
#if defined(TARGET_ARCH_ARM64)

#include "dobby_internal.h"

#include "core/modules/assembler/assembler-arm64.h"
#include "core/modules/codegen/codegen-arm64.h"

#include "InstructionRelocation/arm64/ARM64InstructionRelocation.h"

#include "InterceptRouting/ExtraInternalPlugin/NearBranchTrampoline/NearMemoryArena.h"
#include "InterceptRouting/ExtraInternalPlugin/RegisterPlugin.h"

using namespace zz::arm64;

CodeBufferBase *GenerateNormalTrampolineBuffer(addr_t from, addr_t to) {
  CodeBufferBase *result = NULL;

  DLOG("Generate trampoline => %p", to);

  TurboAssembler turbo_assembler_((void *)from);
#define _ turbo_assembler_.

  uint64_t distance   = llabs((int64_t)(from - to));
  uint64_t adrp_range = ((uint64_t)1 << (2 + 19 + 12 - 1));
  if (distance < adrp_range) {
    // adrp, add, br
    _ AdrpAdd(Register::X(17), from, to);
    _ br(Register::X(17));
    DLOG("Trampoline use [Adrp, Add, Br] combine");
  } else {
    // ldr, br, branch-address
    CodeGen codegen(&turbo_assembler_);
    codegen.LiteralLdrBranch((uint64_t)to);
    DLOG("Trampoline use [Ldr, Br, Label] combine");
  }
  result = turbo_assembler_.GetCodeBuffer()->copy();
  return result;
}

#define ARM64_TINY_REDIRECT_SIZE (4 * 4)
#define ARM64_B_XXX_RANGE ((1 << 25) << 2) // signed

// If BranchType is B_Branch and the branch_range of `B` is not enough, build the transfer to forward the b branch, if
static AssemblyCode *GenerateFastForwardTrampoline(addr_t source_address, addr_t target_address) {
  AssemblyCode *result         = NULL;
  AssemblyCodeChunk *codeChunk = NULL;

  codeChunk = NearMemoryArena::AllocateCodeChunk((addr_t)source_address, ARM64_B_XXX_RANGE, ARM64_TINY_REDIRECT_SIZE);
  if (codeChunk == nullptr) {
    ERROR_LOG("Can't found near code chunk");
    return NULL;
  }

  TurboAssembler turbo_assembler_(0);
  turbo_assembler_.CommitRealizeAddress(codeChunk->address);

  CodeGen codegen(&turbo_assembler_);
  // forward trampoline => target address
  codegen.LiteralLdrBranch(target_address);

  result = AssemblyCode::FinalizeFromTurboAssember(&turbo_assembler_);
  return result;
}

CodeBufferBase *GenerateNearTrampolineBuffer(InterceptRouting *routing, addr_t src, addr_t dst) {
  CodeBufferBase *result = NULL;

  TurboAssembler turbo_assembler_((void *)src);
#define _ turbo_assembler_.

  // branch to trampoline_target directly
  if (llabs((long long)dst - (long long)src) < ARM64_B_XXX_RANGE) {
    _ b(dst - src);
  } else {
    AssemblyCode *fast_forward_trampoline = NULL;
    fast_forward_trampoline               = GenerateFastForwardTrampoline(src, dst);
    if (!fast_forward_trampoline)
      return NULL;
    // trampoline => fast_forward_trampoline
    addr_t fast_forward_trampoline_addr = fast_forward_trampoline->raw_instruction_start();
    _ b(fast_forward_trampoline_addr - src);
  }

  // free the original trampoline
  result = turbo_assembler_.GetCodeBuffer()->copy();
  return result;
}

#endif
