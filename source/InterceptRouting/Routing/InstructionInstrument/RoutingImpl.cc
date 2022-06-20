
#include "dobby_internal.h"

#include "TrampolineBridge/ClosureTrampolineBridge/ClosureTrampoline.h"

#include "InterceptRouting/Routing/InstructionInstrument/InstructionInstrumentRouting.h"
#include "InterceptRouting/Routing/InstructionInstrument/instrument_routing_handler.h"

void InstructionInstrumentRouting::BuildRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *closure_trampoline;

  void *handler = (void *)instrument_routing_dispatch;

#if __APPLE__ && __has_feature(ptrauth_calls)
  handler = ptrauth_strip(handler, ptrauth_key_asia);
#endif

  closure_trampoline = ClosureTrampoline::CreateClosureTrampoline(entry_, handler);
  this->SetTrampolineTarget((addr_t)closure_trampoline->address);
  DLOG(0, "[closure trampoline] data %p ", entry_);
  DLOG(0, "[closure trampoline] closure trampoline %p", closure_trampoline->address);

  // generate trampoline buffer, run before `GenerateRelocatedCode`
  GenerateTrampolineBuffer(entry_->patched_addr, GetTrampolineTarget());
}

void InstructionInstrumentRouting::DispatchRouting() {
  BuildRouting();

  // generate relocated code which size == trampoline size
  GenerateRelocatedCode();
}

#if 0
void *InstructionInstrumentRouting::GetTrampolineTarget() {
  return this->prologue_dispatch_bridge;
}
#endif
