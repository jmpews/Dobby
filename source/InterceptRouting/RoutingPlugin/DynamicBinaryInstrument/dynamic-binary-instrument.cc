#include "InterceptRouting/RoutingPlugin/DynamicBinaryInstrument/dynamic-binary-instrument.h"

#include "dobby_internal.h"

#include "TrampolineBridge/ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "InterceptRouting/RoutingPlugin/DynamicBinaryInstrument/intercept_routing_handler.h"

void DynamicBinaryInstrumentRouting::Dispatch() {
  Prepare();
  BuildDynamicBinaryInstrumentRouting();
}

// Add dbi_call handler before running the origin instructions
void DynamicBinaryInstrumentRouting::BuildDynamicBinaryInstrumentRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *closure_trampoline;
  // forward trampoline
  closure_trampoline = ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)instrument_routing_dispatch);
  DLOG(1, "[closure bridge] Carry data %p ", entry_);
  DLOG(1, "[closure bridge] Create prologue_dispatch_bridge %p", closure_trampoline->address);

  // set trampoline target address
  this->SetTrampolineTarget(closure_trampoline->address);

  this->prologue_dispatch_bridge = closure_trampoline->address;

  GenerateTrampolineBuffer(entry_->target_address, GetTrampolineTarget());

  GenerateRelocatedCode();
}

#if 0
void *DynamicBinaryInstrumentRouting::GetTrampolineTarget() {
  return this->prologue_dispatch_bridge;
}
#endif
