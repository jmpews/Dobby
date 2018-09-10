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
#else
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
  _ stp(X(23), X(24), MEM(SP, 22 * 8));
  _ stp(X(21), X(22), MEM(SP, 20 * 8));
  _ stp(X(19), X(20), MEM(SP, 18 * 8));
  _ stp(X(17), X(18), MEM(SP, 16 * 8));
  _ stp(X(15), X(16), MEM(SP, 14 * 8));
  _ stp(X(13), X(14), MEM(SP, 12 * 8));
  _ stp(X(11), X(12), MEM(SP, 10 * 8));
  _ stp(X(9), X(10), MEM(SP, 8 * 8));
  _ stp(X(7), X(8), MEM(SP, 6 * 8));
  _ stp(X(5), X(6), MEM(SP, 4 * 8));
  _ stp(X(3), X(4), MEM(SP, 2 * 8));
  _ stp(X(1), X(2), MEM(SP, 0 * 8));

  _ PseudoBind(&ClosureTrampolineEntryPtr);
  _ EmitInt64(0); // dummy address

#endif
  return (void *)closure_bridge;
}
