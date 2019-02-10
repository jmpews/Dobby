#include "hookzz_internal.h"

#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "InstructionRelocation/x64/X64InstructionRelocation.h"

#include "core/modules/assembler/assembler-x64.h"
#include "core/modules/codegen/codegen-x64.h"

#include "InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.h"

void FunctionInlineReplaceRouting::Dispatch() {
  Prepare();
  BuildReplaceRouting();
}

void FunctionInlineReplaceRouting::BuildReplaceRouting() {
}

void *FunctionInlineReplaceRouting::GetTrampolineTarget() {
  return entry_->replace_call;
}
