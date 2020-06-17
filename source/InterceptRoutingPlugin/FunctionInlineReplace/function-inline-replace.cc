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
  // hijack trampoline
  this->trampoline_ = (CodeBufferBase *)GenTrampoline(entry_->target_address, GetTrampolineTarget());
  DLOG("create 'hijack trampoline' %p\n", this->trampoline_);
}

void *FunctionInlineReplaceRouting::GetTrampolineTarget() {
  return this->replace_call;
}
