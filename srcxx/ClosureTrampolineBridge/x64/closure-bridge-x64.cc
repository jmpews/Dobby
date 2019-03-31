#include "ExecMemory/AssemblyCode.h"

#include "core/modules/assembler/assembler.h"
#include "core/modules/assembler/assembler-x64.h"
#include "core/arch/x64/registers-x64.h"

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

  __ EmitBuffer(pushfq, 1);

#endif
  return (void *)closure_bridge;
}