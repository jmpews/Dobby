#include "platform_detect_macro.h"
#if defined(TARGET_ARCH_ARM64)

#include "dobby/dobby_internal.h"
#include "core/assembler/assembler-arm64.h"
#include "TrampolineBridge/ClosureTrampolineBridge/ClosureTrampoline.h"
#include "TrampolineBridge/ClosureTrampolineBridge/common_bridge_handler.h"

using namespace zz;
using namespace zz::arm64;

extern "C" void closure_trampoline_asm();
extern "C" void closure_trampoline_asm_end();

ClosureTrampoline *GenerateClosureTrampoline(void *carry_data, void *carry_handler) {
  auto closure_tramp = new ClosureTrampoline(CLOSURE_TRAMPOLINE_ARM64, CodeMemBlock{}, carry_data, carry_handler);

  if (!closure_bridge_addr) {
    closure_bridge_init();
  }

#if !defined(BUILD_WITH_TRAMPOLINE_ASSEMBLER) || defined(BUILD_WITH_TRAMPOLINE_ASM)
  auto closure_trampoline_asm_end_addr = (addr_t)closure_trampoline_asm_end;
  features::apple::arm64e_pac_strip(closure_trampoline_asm_end_addr);
  auto closure_trampoline_asm_addr = (addr_t)closure_trampoline_asm;
  features::apple::arm64e_pac_strip(closure_trampoline_asm_addr);

  auto tramp_size = closure_trampoline_asm_end_addr - closure_trampoline_asm_addr;
  uint8_t tramp_buf[64] = {0};
  memcpy(tramp_buf, (void *)closure_trampoline_asm_addr, tramp_size);
  const uint32_t closure_tramp_off = 9 * 4;
  const uint32_t closure_bridge_addr_off = closure_tramp_off + 8;
  *(addr_t *)(tramp_buf + closure_tramp_off) = (addr_t)closure_tramp;
  *(addr_t *)(tramp_buf + closure_bridge_addr_off) = (addr_t)closure_bridge_addr;
  auto tramp_block = gMemoryAllocator.allocExecBlock(tramp_size);
  DobbyCodePatch((void *)tramp_block.addr(), tramp_buf, tramp_size);
#else
  TurboAssembler turbo_assembler_;
#define _ turbo_assembler_. // NOLINT: clang-tidy

  auto closure_bridge_addr = (addr_t)get_closure_bridge_addr();
  auto closure_bridge_data_label = _ createDataLabel(closure_bridge_addr);

  PseudoLabel entry_label;

  // prologue: alloc stack, store lr
  _ sub(SP, SP, 2 * 8);
  _ str(x30, MemOperand(SP, 8));

  // store data at stack
  _ Ldr(TMP_REG_0, &entry_label);
  _ str(TMP_REG_0, MemOperand(SP, 0));

  _ Ldr(TMP_REG_0, closure_bridge_data_label);
  _ blr(TMP_REG_0);

  // epilogue: release stack(won't restore lr)
  _ ldr(x30, MemOperand(SP, 8));
  _ add(SP, SP, 2 * 8);

  // branch to next hop
  _ br(TMP_REG_0);

  _ bindLabel(&entry_label);
  _ EmitInt64((uint64_t)tramp_entry);

  _ relocDataLabels();

  auto tramp_code_block =
      AssemblerCodeBuilder::FinalizeFromTurboAssembler(static_cast<AssemblerBase *>(&turbo_assembler_));
#endif

  closure_tramp->buffer = tramp_block;
  DEBUG_LOG("closure trampoline addr: %p, size: %d", closure_tramp->addr(), closure_tramp->size());
  debug_hex_log_buffer((uint8_t *)closure_tramp->addr(), closure_tramp->size());
  return closure_tramp;
}

#endif
