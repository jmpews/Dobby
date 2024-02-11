#include "platform_detect_macro.h"
#if defined(TARGET_ARCH_ARM64)

#include "dobby/dobby_internal.h"

#include "core/assembler/assembler-arm64.h"
#include "core/codegen/codegen-arm64.h"

#include "MemoryAllocator/NearMemoryAllocator.h"
#include "InstructionRelocation/arm64/InstructionRelocationARM64.h"
#include "InterceptRouting/RoutingPlugin.h"

using namespace zz::arm64;

#define assert(x)                                                                                                      \
  if (!(x)) {                                                                                                          \
    *(int *)0x41414141 = 0;                                                                                            \
  }

#define ARM64_B_XXX_RANGE ((1ull << 25) << 2) // signed

static Trampoline *GenerateFastForwardTrampoline(addr_t src, addr_t dst) {
  __FUNC_CALL_TRACE__();
  DEBUG_LOG("fast forward trampoline: %p -> %p", src, dst);

  TurboAssembler turbo_assembler_;
#undef _
#define _ turbo_assembler_. // NOLINT: clang-tidy

  // [ldr + br + #label]
  auto forward_tramp_insns_needed = 4 * 4;
  auto blk = gNearMemoryAllocator.allocNearCodeBlock(forward_tramp_insns_needed, src, ARM64_B_XXX_RANGE);
  assert(blk.addr() % 4 == 0 && "address must be aligned to 4 bytes");
  if (!blk.addr()) {
    ERROR_LOG("search near code block failed");
    return {};
  }

  _ ldr(TMP_REG_0, 8);
  _ br(TMP_REG_0);
  _ EmitInt64((uint64_t)dst);

  turbo_assembler_.fixed_addr = blk.addr();
  auto forward_tramp_block = AssemblerCodeBuilder::FinalizeFromTurboAssembler(&turbo_assembler_);
  auto forward_tramp = new Trampoline(FORWARD_TRAMPOLINE_ARM64, forward_tramp_block);
  DEBUG_LOG("[forward trampoline] trampoline addr: %p, size: %d", forward_tramp->addr(), forward_tramp->size());
  debug_hex_log_buffer((uint8_t *)forward_tramp->addr(), forward_tramp->size());
  return forward_tramp;
}

Trampoline *GenerateNearTrampolineBuffer(addr_t src, addr_t dst) {
  __FUNC_CALL_TRACE__();
  DEBUG_LOG("near trampoline: %p -> %p", src, dst);

  TurboAssembler turbo_assembler_(src);
#define _ turbo_assembler_. // NOLINT: clang-tidy

  int tramp_type = 0;
  Trampoline *forward_tramp = nullptr;
  if (llabs((long long)dst - (long long)src) < ARM64_B_XXX_RANGE) {
    tramp_type = TRAMPOLINE_ARM64_B_XXX;
    DEBUG_LOG("[near trampoline] use [b, #label]");
    _ b(dst - src);
  } else {
    tramp_type = TRAMPOLINE_ARM64_B_XXX_AND_FORWARD_TRAMP;
    DEBUG_LOG("[near trampoline] use [b, #label] and forward trampoline");
    forward_tramp = GenerateFastForwardTrampoline(src, dst);
    if (!forward_tramp)
      return nullptr;
    _ b(forward_tramp->addr() - src);
  }

  auto tramp_buffer = turbo_assembler_.code_buffer();
  auto tramp_block = tramp_buffer->dup();
  auto tramp = new Trampoline(tramp_type, tramp_block, forward_tramp);
  DEBUG_LOG("[near trampoline] trampoline addr: %p(temp), %p(real), size: %d", tramp->addr(), src, tramp->size());
  debug_hex_log_buffer((uint8_t *)tramp->addr(), tramp->size());
  return tramp;
}

#endif
