#include "hookzz_internal.h"

#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "intercept_routing_handler.h"

#include "InstructionRelocation/arm64/ARM64InstructionRelocation.h"

#include "core/modules/assembler/assembler-arm64.h"
#include "core/modules/codegen/codegen-arm64.h"

#include "InterceptRouting/FunctionWrapper/function-wrapper-arm64.h"

void FunctionWrapperRouting::Prepare() {
  uint64_t src_address         = (uint64_t)entry_->target_address;
  Interceptor *interceptor     = Interceptor::SharedInstance();
  int relocate_size            = 0;
  AssemblyCodeChunk *codeChunk = NULL;

  DLOG("%s", "[*] Use ARM64 Ldr Branch.\n");
  branch_type_  = ARM64_LDR_Branch;
  relocate_size = ARM64_FULL_REDIRECT_SIZE;

  // Gen the relocated code
  AssemblyCode *code;
  code = GenRelocateCode((void *)src_address, (uint32_t)(ALIGN(src_address, 2)), 0, &relocate_size);
  entry_->relocated_origin_function = (void *)code->raw_instruction_start();
  DLOG("[*] Relocate origin (prologue) instruction at %p.\n", (void *)code->raw_instruction_start());

  // save original prologue
  memcpy(entry_->origin_instructions.data, entry_->target_address, relocate_size);
  entry_->origin_instructions.size    = relocate_size;
  entry_->origin_instructions.address = entry_->target_address;
}

// Active routing, will patch the origin insturctions, and forward to our custom routing.
void FunctionWrapperRouting::Active() {
  uint64_t target_address = (uint64_t)entry_->target_address;
  TurboAssembler turbo_assembler_;
#define _ turbo_assembler_.
  CodeGen codegen(&turbo_assembler_);
  codegen.LiteralLdrBranch((uint64_t)entry_->prologue_dispatch_bridge);

  MemoryOperationError err;
  err = CodePatchTool::PatchCodeBuffer((void *)target_address,
                                       reinterpret_cast<CodeBufferBase *>(turbo_assembler_.GetCodeBuffer()));
  CHECK_EQ(err, kMemoryOperationSuccess);
  AssemblyCode::FinalizeFromAddress(target_address, turbo_assembler_.GetCodeBuffer()->getSize());

  DLOG("[*] Active the FunctionWrapperRouting at %p\n", entry_->target_address);
}