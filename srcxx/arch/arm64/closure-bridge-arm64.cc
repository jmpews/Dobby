#include "vm_core/modules/assembler/assembler.h"
#include "vm_core/arch/arm64/registers-arm64.h"

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
#elif
#define _ assembler_->
#define MEM(reg, offset) LoadStoreAddress(reg, offset)
  Assembler *assembler_;

  // save {q0-q7}
  _ sub(SP, SP, 8 * 16);
  _ stp(Q(6), Q(7), MEM(SP, 6 * 16));
  _ stp(Q(4), Q(5), MEM(SP, 4 * 16));
  _ stp(Q(2), Q(3), MEM(SP, 2 * 16));
  _ stp(Q(0), Q(1), MEM(SP, 2 * 16));

  // save {x1-x30}
  _ sub(SP, SP, 30 * 8);
  _ stp(X(29), X(30), MEM(SP, 28 * 8));
  _ stp(X(27), X(28), MEM(SP, 26 * 8));
  _ stp(X(25), X(26), MEM(SP, 24 * 8));

  _ PseudoBind(&ClosureTrampolineEntryPtr);
  _ EmitInt64(0); // dummy address

#endif
  return (void *)closure_bridge;
}
