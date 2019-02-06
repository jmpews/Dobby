#include "hookzz_internal.h"

#include "ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "AssemblyClosureTrampoline.h"

#include "intercept_routing_handler.h"

#include "InstructionRelocation/x64/X64InstructionRelocation.h"

#include "core/modules/assembler/assembler-x64.h"
#include "core/modules/codegen/codegen-x64.h"

#include "InterceptRoutingPlugin/DynamicBinaryInstrument/dynamic-binary-instrument-x64.h"

void DynamicBinaryInstrumentRouting::Dispatch() {
  Prepare();
  BuildDynamicBinaryInstrumentRouting();
}

// Add dbi_call handler before running the origin instructions
void DynamicBinaryInstrumentRouting::BuildDynamicBinaryInstrumentRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *closure_trampoline_entry =
      ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)instrument_routing_dispatch);
  prologue_dispatch_bridge = closure_trampoline_entry->address;

  DLOG("[*] create dynamic binary instrumentation call closure trampoline to 'prologue_dispatch_bridge' %p\n",
       closure_trampoline_entry->address);
}

void *DynamicBinaryInstrumentRouting::GetTrampolineTarget() {
  return prologue_dispatch_bridge;
}