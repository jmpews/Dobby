
#include "hookzz_internal.h"

#include "ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "AssemblyClosureTrampoline.h"

#include "InterceptRouting/x64/X64InterceptRouting.h"

#include "InstructionRelocation/x64/X64InstructionRelocation.h"

#include "core/modules/assembler/assembler-x64.h"
#include "core/modules/codegen/codegen-x64.h"

using namespace zz::x64;

#define X64_JMP_IMM_SIZE 5

void X64InterceptRouting::Prepare() {
  uint64_t src_address     = (uint64_t)entry_->target_address;
  Interceptor *interceptor = Interceptor::SharedInstance();
  int relocate_size        = X64_JMP_IMM_SIZE;

  // Gen the relocated code
  AssemblyCode *code;
  code                              = GenRelocateCode(src_address, &relocate_size);
  entry_->relocated_origin_function = (void *)code->raw_instruction_start();
  DLOG("[*] Relocate origin (prologue) instruction at %p.\n", (void *)code->raw_instruction_start());

  // save original prologue
  memcpy(entry_->origin_instructions.data, entry_->target_address, relocate_size);
  entry_->origin_instructions.size    = relocate_size;
  entry_->origin_instructions.address = entry_->target_address;
}

// Active routing, will patch the origin insturctions, and forward to our custom routing.
void X64InterceptRouting::Active() {
  uint64_t target_address = (uint64_t)entry_->target_address;
  uint64_t branch_address = (uint64_t)GetTrampolineTarget();

  TurboAssembler turbo_assembler_;
#define _ turbo_assembler_.

  CodeGen codegen(&turbo_assembler_);
  turbo_assembler_.CommitRealizeAddress((void *)target_address);

  codegen.JmpBranch((addr_t)branch_address);

  MemoryOperationError err;
  err = CodePatchTool::PatchCodeBuffer((void *)target_address,
                                       reinterpret_cast<CodeBufferBase *>(turbo_assembler_.GetCodeBuffer()));
  CHECK_EQ(err, kMemoryOperationSuccess);
  AssemblyCode::FinalizeFromAddress(target_address, turbo_assembler_.GetCodeBuffer()->getSize());

  DLOG("[*] Active the routing at %p\n", entry_->target_address);
}
