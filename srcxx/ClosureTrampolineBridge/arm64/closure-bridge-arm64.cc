#include "ExecMemory/AssemblyCode.h"

#include "core/modules/assembler/assembler.h"
#include "core/modules/assembler/assembler-arm64.h"

#include "ClosureTrampolineBridge/closure-trampoline-common-handler/closure-trampoline-common-handler.h"

using namespace zz;
using namespace zz::arm64;

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
  TurboAssembler turbo_assembler_(0);

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

#if 1
  // save {x0}
  _ sub(SP, SP, 2 * 8);
  _ str(x0, MEM(SP, 8));
#else
// Ignore, refer: closure_bridge_template
#endif

  _ mov(x0, SP);
  _ mov(x1, TMP1);
  _ CallFunction(ExternalReference((void *)intercept_routing_common_bridge_handler));

  // ======= RegisterContext Restore =======
  // restore x0
  _ ldr(X(0), MEM(SP, 8));
  _ add(SP, SP, 2 * 8);
  // restore {x1-x30}
  _ ldp(X(1), X(2), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(3), X(4), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(5), X(6), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(7), X(8), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(9), X(10), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(11), X(12), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(13), X(14), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(15), X(16), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(17), X(18), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(19), X(20), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(21), X(22), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(23), X(24), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(25), X(26), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(27), X(28), MEM_EXT(SP, 16, PostIndex));
  _ ldp(X(29), X(30), MEM_EXT(SP, 16, PostIndex));
  // restore {q0-q7}
  _ ldp(Q(0), Q(1), MEM_EXT(SP, 32, PostIndex));
  _ ldp(Q(2), Q(3), MEM_EXT(SP, 32, PostIndex));
  _ ldp(Q(4), Q(5), MEM_EXT(SP, 32, PostIndex));
  _ ldp(Q(6), Q(7), MEM_EXT(SP, 32, PostIndex));

  // _ brk(0); // for debug

  // branch to next hop, @modify by `xxx_routing_dispatch`
  _ br(x16);

  AssemblyCode *code = AssemblyCode::FinalizeFromTurboAssember(&turbo_assembler_);
  closure_bridge     = (void *)code->raw_instruction_start();

  DLOG("[*] Build the closure bridge at %p\n", closure_bridge);

#endif
  return (void *)closure_bridge;
}
