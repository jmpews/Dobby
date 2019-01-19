#include "AssemblyClosureTrampoline.h"

#include "AssemblyBridge.h"

extern void closure_trampoline_template();

using namespace zz;

ClosureTrampolineEntry *ClosureTrampoline::CreateClosureTrampoline(void *carry_data, void *carry_handler) {

  ClosureTrampolineEntry *entry = new ClosureTrampolineEntry;
  return NULL;
}
