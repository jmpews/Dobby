#include "InterceptRouting/Routing/DynamicBinaryInstrument/dynamic-binary-instrument.h"

#include "dobby_internal.h"

#include "TrampolineBridge/ClosureTrampolineBridge/ClosureTrampoline.h"

#include "InterceptRouting/Routing/DynamicBinaryInstrument/intercept_routing_handler.h"

void DynamicBinaryInstrumentRouting::DispatchRouting() {
  BuildDynamicBinaryInstrumentRouting();

  // generate relocated code which size == trampoline size
  GenerateRelocatedCode(trampoline_buffer_->GetBufferSize());
}

// Add dbi_call handler before running the origin instructions
void DynamicBinaryInstrumentRouting::BuildDynamicBinaryInstrumentRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *closure_trampoline;

  void *handler = (void *)instrument_routing_dispatch;
  
#if __APPLE__ && __has_feature(ptrauth_calls)
  handler = ptrauth_strip(handler, ptrauth_key_asia);
#endif

  closure_trampoline = ClosureTrampoline::CreateClosureTrampoline(entry_, handler);
  this->SetTrampolineTarget(closure_trampoline->address);
  DLOG(0, "[closure trampoline] data %p ", entry_);
  DLOG(0, "[closure trampoline] closure trampoline %p", closure_trampoline->address);

  // generate trampoline buffer, run before `GenerateRelocatedCode`
  GenerateTrampolineBuffer(entry_->target_address, GetTrampolineTarget());
}

#if 0
void *DynamicBinaryInstrumentRouting::GetTrampolineTarget() {
  return this->prologue_dispatch_bridge;
}
#endif
