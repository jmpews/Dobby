#include "dobby_internal.h"

#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.h"

void FunctionInlineReplaceRouting::Dispatch() {
  Prepare();
  BuildReplaceRouting();
}

void FunctionInlineReplaceRouting::BuildReplaceRouting() {
  // direct => replace call
  this->SetTrampolineTarget(this->replace_call);
  LOG("Set trampoline target => %p", GetTrampolineTarget());

  GenerateTrampolineBuffer(entry_->target_address, GetTrampolineTarget());
}

#if 0
void *FunctionInlineReplaceRouting::GetTrampolineTarget() {
  return this->replace_call;
}
#endif
