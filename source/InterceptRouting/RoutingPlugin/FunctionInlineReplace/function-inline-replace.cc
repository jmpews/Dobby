#include "InterceptRouting/RoutingPlugin/FunctionInlineReplace/function-inline-replace.h"

#include "dobby_internal.h"

void FunctionInlineReplaceRouting::Dispatch() {
  Prepare();
  BuildReplaceRouting();
}

void FunctionInlineReplaceRouting::BuildReplaceRouting() {
  // direct => replace call
  this->SetTrampolineTarget(this->replace_call);
  DLOG(0, "Set trampoline target => %p", GetTrampolineTarget());

  GenerateTrampolineBuffer(entry_->target_address, GetTrampolineTarget());

  GenerateRelocatedCode();
}

#if 0
void *FunctionInlineReplaceRouting::GetTrampolineTarget() {
  return this->replace_call;
}
#endif
