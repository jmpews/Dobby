#include "dobby_internal.h"

#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "intercept_routing_handler.h"

#include "InterceptRoutingPlugin/FunctionWrapper/function-wrapper.h"

void FunctionWrapperRouting::Dispatch() {
  Prepare();
  BuildPreCallRouting();
  BuildPostCallRouting();
}

// Add pre_call(prologue) handler before running the origin function,
void FunctionWrapperRouting::BuildPreCallRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *cte = ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)prologue_routing_dispatch);
  this->prologue_dispatch_bridge = cte->address;

  DLOG("create pre call closure trampoline to 'prologue_routing_dispatch' at %p\n", cte->address);
}

// Add post_call(epilogue) handler before `Return` of the origin function, as implementation is replace the origin `Return Address` of the function.
void FunctionWrapperRouting::BuildPostCallRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *closure_trampoline_entry;
  // format trampoline
  closure_trampoline_entry = ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)epilogue_routing_dispatch);
  DLOG("create post call closure trampoline to 'prologue_routing_dispatch' at %p\n", closure_trampoline_entry->address);

  // hijack trampoline
  this->trampoline = (CodeBufferBase *)GenTrampoline(entry_->target_address, GetTrampolineTarget());
  DLOG("create 'hijack trampoline' %p\n", this->trampoline);

  this->epilogue_dispatch_bridge = closure_trampoline_entry->address;
}

void *FunctionWrapperRouting::GetTrampolineTarget() {
  return this->prologue_dispatch_bridge;
}
