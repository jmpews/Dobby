#include "hookzz_internal.h"

#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.h"

void FunctionInlineReplaceRouting::Dispatch() {
  Prepare();
  BuildReplaceRouting();
}

void FunctionInlineReplaceRouting::BuildReplaceRouting() {
}

void *FunctionInlineReplaceRouting::GetTrampolineTarget() {
  return this->replace_call;
}
