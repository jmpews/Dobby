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

  // save flags register
  __ EmitBuffer(pushfd, 1);
  // align rsp 16-byte
  _ sub(esp, Immediate(4, 32));

  // general register
  _ sub(esp, Immediate(8 * 4, 32));
  _ mov(Address(esp, 8 * 0), eax);
  _ mov(Address(esp, 8 * 1), ebx);
  _ mov(Address(esp, 8 * 2), ecx);
  _ mov(Address(esp, 8 * 3), edx);
  _ mov(Address(esp, 8 * 4), ebp);
  _ mov(Address(esp, 8 * 5), esp);
  _ mov(Address(esp, 8 * 6), edi);
  _ mov(Address(esp, 8 * 7), esi);

  // save origin sp
  _ mov(eax, esp);
  _ add(eax, Immediate(4 + 4 + 4 + 8 * 4, 32));
  _ sub(esp, Immediate(2 * 4, 32));
  _ mov(Address(esp, 8), eax);

  // ======= Jump to UnifiedInterface Bridge Handle =======

  // prepare args

  // [!!!] As we can't detect the sp is aligned or not, check if need stack align
  {
    //  mov eax, esp
    __ EmitBuffer((void *)"\x89\xE0", 2);
    //  and eax, 0x7
    __ EmitBuffer((void *)"\x83\xE0\x07", 3);
    //  cmp eax, 0x0
    __ EmitBuffer((void *)"\x83\xF8\x00", 3);
    // jnz [stack_align_call_bridge]
    __ EmitBuffer((void *)"\x75\x15", 2);
  }

  // LABEL: call_bridge
  _ CallFunction(ExternalReference((void *)intercept_routing_common_bridge_handler));

  // jmp [restore_stack_register]
  __ EmitBuffer((void *)"\xE9\x12\x00\x00\x00", 5);

  // LABEL: stack_align_call_bridge
  // push eax
  __ EmitBuffer((void *)"\x50", 1);
  _ CallFunction(ExternalReference((void *)intercept_routing_common_bridge_handler));
  // pop eax
  __ EmitBuffer((void *)"\x58", 1);

  // ======= RegisterContext Restore =======

  // restore sp placeholder stack
  _ add(esp, Immediate(2 * 4, 32));

  // general register
  _ pop(eax);
  _ pop(ebx);
  _ pop(ecx);
  _ pop(edx);
  _ pop(ebp);
  _ add(esp, Immediate(4, 32)); // => pop rsp
  _ pop(edi);
  _ pop(esi);

  // align rsp 16-byte
  _ add(esp, Immediate(4, 32));
  // restore flags register
  __ EmitBuffer(popfd, 1);

  // trick: use the 'carry_data' stack(remain at closure trampoline) placeholder, as the return address
  _ ret();

  _ RelocBind();

  AssemblyCodeChunk *code = AssemblyCodeBuilder::FinalizeFromTurboAssembler(&turbo_assembler_);
  closure_bridge = (void *)code->raw_instruction_start();

  DLOG(0, "Build the closure bridge at %p", closure_bridge);

#endif
  return (void *)closure_bridge;
}

#endif