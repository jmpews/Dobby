#include "common/macros/platform_macro.h"
#if defined(TARGET_ARCH_IA32)

#include "dobby_internal.h"

#include "core/modules/assembler/assembler.h"
#include "core/modules/assembler/assembler-ia32.h"

#include "ClosureTrampolineBridge/closure-trampoline-common-handler/closure-trampoline-common-handler.h"

using namespace zz;
using namespace zz::x86;

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
#define _  turbo_assembler_.
#define __ turbo_assembler_.GetCodeBuffer()->

  char *pushfd = (char *)"\x9c";
  char *popfd = (char *)"\x9d";

  TurboAssembler turbo_assembler_(0);

  // general register
  _ sub(esp, Immediate(8 * 4, 32));
  _ mov(Address(esp, 4 * 0), eax);
  _ mov(Address(esp, 4 * 1), ebx);
  _ mov(Address(esp, 4 * 2), ecx);
  _ mov(Address(esp, 4 * 3), edx);
  _ mov(Address(esp, 4 * 4), ebp);
  _ mov(Address(esp, 4 * 5), esp);
  _ mov(Address(esp, 4 * 6), edi);
  _ mov(Address(esp, 4 * 7), esi);

  // save flags register
  __ EmitBuffer(pushfd, 1);
  _ pop(eax);
  { // save to stack
    _ sub(esp, Immediate(2 * 4, 32));
    _ mov(Address(esp, 4), eax);
  }

  // save origin sp
  _ mov(eax, esp);
  _ add(eax, Immediate(8 * 4 + 2 * 4 + 4, 32));
  { // save to stack
    _ sub(esp, Immediate(2 * 4, 32));
    _ mov(Address(esp, 4), eax);
  }

  // ======= Jump to UnifiedInterface Bridge Handle =======

  // prepare args
  _ sub(esp, Immediate(2 * 4, 32));
  _ mov(eax, Address(esp, 8 * 4 + 2 * 4 + 2 * 4 + 2 * 4));
  _ mov(Address(esp, 4), eax);
  _ mov(eax, esp);
  _ add(eax, Immediate(2 * 4, 32));
  _ mov(Address(esp, 0), eax);

  // LABEL: call_bridge
  _ CallFunction(ExternalReference((void *)intercept_routing_common_bridge_handler));

  // ======= RegisterContext Restore =======

  // restore argument reserved stack
  _ add(esp, Immediate(2 * 4, 32));

  // restore sp placeholder stack
  _ add(esp, Immediate(2 * 4, 32));

  _ add(esp, Immediate(4, 32));
  // restore flags register
  __ EmitBuffer(popfd, 1);

  // general register
  _ pop(eax);
  _ pop(ebx);
  _ pop(ecx);
  _ pop(edx);
  _ pop(ebp);
  _ add(esp, Immediate(4, 32)); // => pop rsp
  _ pop(edi);
  _ pop(esi);

  // trick: use the 'carry_data' stack(remain at closure trampoline) placeholder, as the return address
  _ ret();

  _ RelocBind();

  AssemblyCodeChunk *code = AssemblyCodeBuilder::FinalizeFromTurboAssembler(&turbo_assembler_);
  closure_bridge = (void *)code->raw_instruction_start();

  DLOG(1, "[closure bridge] Build the closure bridge at %p", closure_bridge);
#endif
  return (void *)closure_bridge;
}

#endif