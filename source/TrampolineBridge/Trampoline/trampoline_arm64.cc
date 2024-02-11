#include "platform_detect_macro.h"
#if defined(TARGET_ARCH_ARM64)

#include "dobby/dobby_internal.h"

#include "core/assembler/assembler-arm64.h"
#include "core/codegen/codegen-arm64.h"

#include "MemoryAllocator/NearMemoryAllocator.h"
#include "InstructionRelocation/arm64/InstructionRelocationARM64.h"
#include "InterceptRouting/RoutingPlugin.h"

using namespace zz::arm64;

Trampoline *GenerateNormalTrampolineBuffer(addr_t from, addr_t to) {
  __FUNC_CALL_TRACE__();
  TurboAssembler turbo_assembler_(from);
#undef _
#define _ turbo_assembler_. // NOLINT: clang-tidy

  int tramp_type = 0;
  uint64_t distance = llabs((int64_t)(from - to));
  uint64_t adrp_range = ((uint64_t)1 << (2 + 19 + 12 - 1));
  if (distance < adrp_range) {
    tramp_type = TRAMPOLINE_ARM64_ADRP_ADD_BR;
    _ AdrpAdd(TMP_REG_0, from, to);
    _ br(TMP_REG_0);
    DEBUG_LOG("[trampoline] use [adrp, add, br]");
  } else {
    tramp_type = TRAMPOLINE_ARM64_LDR_BR;
    CodeGen codegen(&turbo_assembler_);
    codegen.LiteralLdrBranch((uint64_t)to);
    DEBUG_LOG("[trampoline] use [ldr, br, #label]");
  }

  // bind all labels
  _ relocDataLabels();

  auto tramp_buffer = turbo_assembler_.code_buffer();
  auto tramp_block = tramp_buffer->dup();
  auto tramp = new Trampoline(tramp_type, tramp_block);
  DEBUG_LOG("[trampoline] trampoline addr: %p(temp), %p(real), size: %d", tramp->addr(), from, tramp->size());
  debug_hex_log_buffer((uint8_t *)tramp->addr(), tramp->size());
  return tramp;
}

#endif
