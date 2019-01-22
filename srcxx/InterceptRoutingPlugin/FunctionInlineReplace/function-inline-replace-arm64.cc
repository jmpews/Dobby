#include "hookzz_internal.h"

#include "ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "AssemblyClosureTrampoline.h"

#include "intercept_routing_handler.h"

#include "InstructionRelocation/arm64/ARM64InstructionRelocation.h"

#include "core/modules/assembler/assembler-arm64.h"
#include "core/modules/codegen/codegen-arm64.h"

#include "InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace-arm64.h"

// Active routing, will patch the origin insturctions, and forward to our custom routing.
void FunctionInlineReplaceRouting::Active() {
  ActiveAt(0);
}

void FunctionInlineReplaceRouting::BuildReplaceRouting() {
}