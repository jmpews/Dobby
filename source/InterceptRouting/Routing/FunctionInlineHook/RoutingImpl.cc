#include "dobby_internal.h"
#include "InterceptRouting/Routing/FunctionInlineHook/FunctionInlineHookRouting.h"

void FunctionInlineHookRouting::BuildRouting() {
  SetTrampolineTarget((addr_t)replace_func);

  // generate trampoline buffer, run before GenerateRelocatedCode
  GenerateTrampolineBuffer(entry_->patched_addr, GetTrampolineTarget());
}

void FunctionInlineHookRouting::DispatchRouting() {
  BuildRouting();

  // generate relocated code which size == trampoline size
  GenerateRelocatedCode();
}
