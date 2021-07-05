#include "platform_macro.h"
#if defined(TARGET_ARCH_ARM64)

#include "dobby_internal.h"

#include "core/assembler/assembler-arm64.h"
#include "core/codegen/codegen-arm64.h"

#include "MemoryAllocator/NearMemoryArena.h"
#include "InstructionRelocation/arm64/InstructionRelocationARM64.h"
#include "InterceptRouting/RoutingPlugin/RoutingPlugin.h"

using namespace zz::arm64;

#define ARM64_B_XXX_RANGE ((1 << 25) << 2) // signed

// If BranchType is B_Branch and the branch_range of `B` is not enough
// build the transfer to forward the b branch
static AssemblyCode *GenerateFastForwardTrampoline(addr_t source_address, addr_t target_address) {
  TurboAssembler turbo_assembler_(nullptr);
#define _ turbo_assembler_.

  // [adrp + add + br branch]
  CodeBlock *block = nullptr;
  block = NearMemoryArena::SharedInstance()->allocNearCodeBlock((addr_t)source_address, ARM64_B_XXX_RANGE, 3 * 4);
  if (block == nullptr) {
    ERROR_LOG("Can't found near code chunk");
    return nullptr;
  }

  // Use adrp + add branch
  uint64_t distance = llabs((int64_t)(block->addr - target_address));
  uint64_t adrp_range = ((uint64_t)1 << (2 + 19 + 12 - 1));
  if (distance < adrp_range) {
    // use adrp + add + br branch == (3 * 4) trampoline size
    _ AdrpAdd(TMP_REG_0, block->addr, target_address);
    _ br(TMP_REG_0);
    DLOG(0, "forward trampoline use [adrp, add, br] combine");
  } else {
    // use mov + br == (4 * 5) trampoline size
    _ Mov(TMP_REG_0, target_address);
    _ br(TMP_REG_0);
    DLOG(0, "forward trampoline use  [mov, br] combine");

    size_t tramp_size = turbo_assembler_.GetCodeBuffer()->GetBufferSize();
    block =
        NearMemoryArena::SharedInstance()->allocNearCodeBlock((addr_t)source_address, ARM64_B_XXX_RANGE, tramp_size);
    if (block == nullptr) {
      ERROR_LOG("Can't found near code chunk");
      return nullptr;
    }
  }

  turbo_assembler_.SetRealizedAddress((void *)block->addr);

  AssemblyCode *code = nullptr;
  code = AssemblyCodeBuilder::FinalizeFromTurboAssembler(&turbo_assembler_);
  return code;
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
    fast_forward_trampoline = GenerateFastForwardTrampoline(src, dst);
    if (!fast_forward_trampoline)
      return NULL;
    // trampoline => fast_forward_trampoline
    addr_t fast_forward_trampoline_addr = (addr_t)fast_forward_trampoline->begin;
    _ b(fast_forward_trampoline_addr - src);
  }

  // free the original trampoline
  result = turbo_assembler_.GetCodeBuffer()->Copy();
  return result;
}

#endif
