
#include "vm_core_extra/custom-code.h"
#include "vm_core_extra/code-page-chunk.h"
#include "vm_core/modules/assembler/assembler.h"

using namespace zz;

#if V8_TARGET_ARCH_ARM
#elif V8_TARGET_ARCH_ARM64
using namespace zz::arm64;
#endif

AssemblerCode *AssemblerCode::FinalizeTurboAssembler(AssemblerBase *assembler) {
  TurboAssembler *turbo_assembler = reinterpret_cast<TurboAssembler *>(assembler);
  int code_size                   = turbo_assembler->CodeSize();
  // Allocate the executable memory
  void *code_address = CodeChunk::AllocateCode(code_size);
  // Realize(Relocate) the buffer_code to the executable_memory_address, remove the ExternalLabels, etc, the pc-relative instructions
  turbo_assembler->CommitRealize(code_address);
  CodeChunk::PatchCodeBuffer(code_address, turbo_assembler->GetCodeBuffer());
  Code *code = turbo_assembler->GetCode();
  return reinterpret_cast<AssemblerCode *>(code);
}