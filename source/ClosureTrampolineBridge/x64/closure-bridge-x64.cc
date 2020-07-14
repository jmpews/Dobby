#include "dobby_internal.h"

#include "core/modules/assembler/assembler.h"
#include "core/modules/assembler/assembler-x64.h"

#include "ClosureTrampolineBridge/closure-trampoline-common-handler/closure-trampoline-common-handler.h"

using namespace zz;
using namespace zz::x64;

static void *closure_bridge = NULL;

void *get_closure_bridge() {
  // if already initialized, just return.
  if (closure_bridge)
    return closure_bridge;

// Check if enable the inline-assembly closure_bridge_template
#if ENABLE_CLOSURE_BRIDGE_TEMPLATE

  extern void closure_bridge_tempate();
  closure_bridge = closure_bridge_template;

#else

// otherwise, use the Assembler build the closure_bridge
#define _ turbo_assembler_.
#define __ turbo_assembler_.GetCodeBuffer()->

  char *pushfq = "\x9c";
  char *popfq = "\x9c";

  TurboAssembler turbo_assembler_(0);

  // flags register
  __ EmitBuffer(pushfq, 1);

  // general register
  _ sub(rsp, Immediate(16 * 8));
  _ mov(Address(rsp, 8 * 0), rax);
  _ mov(Address(rsp, 8 * 1), rbx);
  _ mov(Address(rsp, 8 * 2), rcx);
  _ mov(Address(rsp, 8 * 3), rdx);
  _ mov(Address(rsp, 8 * 4), rbp);
  _ mov(Address(rsp, 8 * 5), rsp);
  _ mov(Address(rsp, 8 * 6), rdi);
  _ mov(Address(rsp, 8 * 7), rsi);
  _ mov(Address(rsp, 8 * 8), r8);
  _ mov(Address(rsp, 8 * 9), r9);
  _ mov(Address(rsp, 8 * 10), r10);
  _ mov(Address(rsp, 8 * 11), r11);
  _ mov(Address(rsp, 8 * 12), r12);
  _ mov(Address(rsp, 8 * 13), r13);
  _ mov(Address(rsp, 8 * 14), r14);
  _ mov(Address(rsp, 8 * 15), r15);

  // ======= Jump to UnifiedInterface Bridge Handle =======

  // prepare args
  // @rdi: data_address
  // @rsi: RegisterContext stack address

  _ mov(rdi, rsp);
  _ mov(rsi, Address(rsp, -16 * 8));
  _ CallFunction(ExternalReference((void *)intercept_routing_common_bridge_handler));


  // ======= RegisterContext Restore =======

  // general register

  _ pop(r15);
  _ pop(r14);
  _ pop(r13);
  _ pop(r12);
  _ pop(r11);
  _ pop(r10);
  _ pop(r9);
  _ pop(r8);
  _ pop(rsi);
  _ pop(rdi);
  _ pop(rsp);
  _ pop(rbp);
  _ pop(rdx);
  _ pop(rcx);
  _ pop(rbx);
  _ pop(rax);

  __ EmitBuffer(popfq, 1);

#endif
  return (void *)closure_bridge;
}