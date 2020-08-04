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

  char *pushfq = (char *)"\x9c";
  char *popfq = (char *)"\x9d";

  TurboAssembler turbo_assembler_(0);

  // save flags register
  __ EmitBuffer(pushfq, 1);
  // align rsp 16-byte
  _ sub(rsp, Immediate(8, 32));

  // general register
  _ sub(rsp, Immediate(16 * 8, 32));
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

  // save origin sp
  _ mov(rax, rsp);
  _ add(rax, 8 + 8 + 16 * 8);
  _ sub(rsp, Immediate(2 * 8, 32));
  _ mov(Address(rsp, 8), rax);

  // ======= Jump to UnifiedInterface Bridge Handle =======

  // prepare args
  // @rdi: data_address
  // @rsi: RegisterContext stack address
  _ mov(rdi, rsp);
  _ mov(rsi, Address(rsp, 16 * 8 + 8 + 8));
  _ CallFunction(ExternalReference((void *)intercept_routing_common_bridge_handler));

  // ======= RegisterContext Restore =======

  // restore sp placeholder stack
  _ add(rsp, Immediate(2 * 8, 32));

  // general register
  _ pop(rax);
  _ pop(rbx);
  _ pop(rcx);
  _ pop(rdx);
  _ pop(rbp);
  _ add(rsp, Immediate(8, 32)); // => pop rsp
  _ pop(rdi);
  _ pop(rsi);
  _ pop(r8);
  _ pop(r9);
  _ pop(r10);
  _ pop(r11);
  _ pop(r12);
  _ pop(r13);
  _ pop(r14);
  _ pop(r15);

  // align rsp 16-byte
  _ add(rsp, Immediate(8, 32));
  // restore flags register
  __ EmitBuffer(popfq, 1);

  // trick: use the 'carry_data' stack(remain at closure trampoline) placeholder, as the return address
  _ ret();

  _ RelocFixup();

  AssemblyCode *code = AssemblyCode::FinalizeFromTurboAssember(&turbo_assembler_);
  closure_bridge = (void *)code->raw_instruction_start();

  DLOG("Build the closure bridge at %p", closure_bridge);

#endif
  return (void *)closure_bridge;
}
