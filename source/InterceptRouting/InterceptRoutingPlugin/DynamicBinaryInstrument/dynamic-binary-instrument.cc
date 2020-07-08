#include "./dynamic-binary-instrument.h"
#include "./intercept_routing_handler.h"

#include "dobby_internal.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

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
  DLOG("Create dynamic binary instrumentation call closure trampoline to prologue_dispatch_bridge(%p)",
       closure_trampoline->address);

  // set trampoline target address
  this->SetTrampolineTarget(closure_trampoline->address);
  DLOG("Set trampoline target => %p", GetTrampolineTarget());

  this->prologue_dispatch_bridge = closure_trampoline->address;

  GenerateTrampolineBuffer(entry_->target_address, GetTrampolineTarget());
  
  GenerateRelocatedCode();
}

#if 0
void *DynamicBinaryInstrumentRouting::GetTrampolineTarget() {
  return this->prologue_dispatch_bridge;
}
#endif
