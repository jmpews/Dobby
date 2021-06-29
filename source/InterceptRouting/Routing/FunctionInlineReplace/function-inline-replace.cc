#include "InterceptRouting/Routing/FunctionInlineReplace/function-inline-replace.h"

#include "dobby_internal.h"

void FunctionInlineReplaceRouting::DispatchRouting() {
  BuildReplaceRouting();

  // generate relocated code which size == trampoline size
  GenerateRelocatedCode(trampoline_buffer_->GetBufferSize());
}

void FunctionInlineReplaceRouting::BuildReplaceRouting() {
  SetTrampolineTarget(this->replace_call);
  // generate trampoline buffer, run before GenerateRelocatedCode
  GenerateTrampolineBuffer(entry_->target_address, GetTrampolineTarget());
}

#if 0
void *FunctionInlineReplaceRouting::GetTrampolineTarget() {
  return this->replace_call;
}
#endif
