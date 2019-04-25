#include "core/arch/arm/registers-arm.h"
#include "core/modules/assembler/assembler.h"
#include "vm_core_extra/custom-code.h"

#include "intercept_routing_handler.h"

using namespace zz;
using namespace zz::arm;

static void *closure_bridge = NULL;

void *get_closure_bridge() {

  // if already initialized, just return.
  if (closure_bridge)
    return closure_bridge;

// check if enable the inline-assembly closure_bridge_template
#if ENABLE_CLOSURE_BRIDGE_TEMPLATE
  extern void closure_bridge_tempate();
  closure_bridge = closure_bridge_template;
// otherwise, use the Assembler build the closure_bridge
#else
#define _ turbo_assembler_.
#define MEM(reg, offset) MemOperand(reg, offset)
#define MEM_EXT(reg, offset, addrmode) MemOperand(reg, offset, addrmode)
  TurboAssembler turbo_assembler_;

  _ sub(sp, sp, Operand(14 * 4));
  _ str(lr, MEM(sp, 13 * 4));
  _ str(r12, MEM(sp, 12 * 4));
  _ str(r11, MEM(sp, 11 * 4));
  _ str(r10, MEM(sp, 10 * 4));
  _ str(r9, MEM(sp, 9 * 4));
  _ str(r8, MEM(sp, 8 * 4));
  _ str(r7, MEM(sp, 7 * 4));
  _ str(r6, MEM(sp, 6 * 4));
  _ str(r5, MEM(sp, 5 * 4));
  _ str(r4, MEM(sp, 4 * 4));
  _ str(r3, MEM(sp, 3 * 4));
  _ str(r2, MEM(sp, 2 * 4));
  _ str(r1, MEM(sp, 1 * 4));
  _ str(r0, MEM(sp, 0 * 4));

  _ sub(sp, sp, Operand(8));

  _ mov(r0, sp);
  _ mov(r1, r12);
  _ CallFunction(ExternalReference((void *)intercept_routing_common_bridge_handler));

  // dummy stack align
  _ add(sp, sp, Operand(8));

  _ ldr(r0, MEM_EXT(sp, 4, PostIndex));
  _ ldr(r1, MEM_EXT(sp, 4, PostIndex));
  _ ldr(r2, MEM_EXT(sp, 4, PostIndex));
  _ ldr(r3, MEM_EXT(sp, 4, PostIndex));
  _ ldr(r4, MEM_EXT(sp, 4, PostIndex));
  _ ldr(r5, MEM_EXT(sp, 4, PostIndex));
  _ ldr(r6, MEM_EXT(sp, 4, PostIndex));
  _ ldr(r7, MEM_EXT(sp, 4, PostIndex));
  _ ldr(r8, MEM_EXT(sp, 4, PostIndex));
  _ ldr(r9, MEM_EXT(sp, 4, PostIndex));
  _ ldr(r10, MEM_EXT(sp, 4, PostIndex));
  _ ldr(r11, MEM_EXT(sp, 4, PostIndex));
  _ ldr(r12, MEM_EXT(sp, 4, PostIndex));
  _ ldr(lr, MEM_EXT(sp, 4, PostIndex));

  // auto switch A32 & T32 with `least significant bit`, refer `docs/A32_T32_states_switch.md`
  _ mov(pc, r12);

  AssemblyCode *code = AssemblyCode::FinalizeTurboAssembler(&turbo_assembler_);
  closure_bridge     = (void *)code->raw_instruction_start();

  HOOKZZ_DLOG("[*] Build the closure bridge at %p\n", closure_bridge);

#endif
  return (void *)closure_bridge;
}
