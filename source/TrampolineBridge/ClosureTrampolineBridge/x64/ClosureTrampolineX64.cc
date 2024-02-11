#include "platform_detect_macro.h"
#if defined(TARGET_ARCH_X64)

#include "dobby/dobby_internal.h"
#include "core/assembler/assembler-x64.h"
#include "TrampolineBridge/ClosureTrampolineBridge/ClosureTrampoline.h"
#include "TrampolineBridge/ClosureTrampolineBridge/common_bridge_handler.h"
#include "MemoryAllocator/NearMemoryAllocator.h"

using namespace zz;
using namespace zz::x64;

extern "C" void closure_trampoline_asm();
extern "C" void closure_trampoline_asm_end();

ClosureTrampoline *GenerateClosureTrampoline(void *carry_data, void *carry_handler) {
  auto closure_tramp = new ClosureTrampoline(CLOSEURE_TRAMPOLINE_X64, CodeMemBlock{}, carry_data, carry_handler);

  if (!closure_bridge_addr) {
    closure_bridge_init();
  }

#if !defined(BUILD_WITH_TRAMPOLINE_ASSEMBLER) || defined(BUILD_WITH_TRAMPOLINE_ASM)
  auto closure_trampoline_asm_end_addr = (addr_t)closure_trampoline_asm_end;
  auto closure_trampoline_asm_addr = (addr_t)closure_trampoline_asm;

  auto tramp_size = closure_trampoline_asm_end_addr - closure_trampoline_asm_addr;
  uint8_t tramp_buf[64] = {0};
  memcpy(tramp_buf, (void *)closure_trampoline_asm_addr, tramp_size);
  const uint32_t closure_tramp_off = 6 + 6;
  const uint32_t closure_bridge_addr_off = closure_tramp_off + 8;
  *(addr_t *)(tramp_buf + closure_tramp_off) = (addr_t)closure_tramp;
  *(addr_t *)(tramp_buf + closure_bridge_addr_off) = (addr_t)closure_bridge_addr;
  auto tramp_block = gMemoryAllocator.allocExecBlock(tramp_size);
  DobbyCodePatch((void *)tramp_block.addr(), tramp_buf, tramp_size);
#else
  auto tramp_size = 32;
  auto blk = gMemoryAllocator.allocExecBlock(tramp_size);
  if (blk.addr() == 0) {
    return nullptr;
  }
#define _ turbo_assembler_.
#define __ turbo_assembler_.code_buffer()->
  TurboAssembler turbo_assembler_(0);

  uint8_t *push_rip_6 = (uint8_t *)"\xff\x35\x06\x00\x00\x00";
  uint8_t *jmp_rip_8 = (uint8_t *)"\xff\x25\x08\x00\x00\x00";

  __ EmitBuffer(push_rip_6, 6);
  __ EmitBuffer(jmp_rip_8, 6);
  __ Emit<uint64_t>((uint64_t)closure_tramp);
  __ Emit<uint64_t>((uint64_t)closure_bridge_addr);

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