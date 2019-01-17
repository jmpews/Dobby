#include "AssemblyCode.h"

#include "ExecutableMemoryArena.h"

#if TARGET_ARCH_ARM
using namespace zz::arm;
#elif TARGET_ARCH_ARM64
using namespace zz::arm64;
#elif TARGET_ARCH_X64
using namespace zz::x64;
#endif

namespace zz {

AssemblyCode *AssemblyCode::FinalizeFromAddress(uintptr_t address, int size) {
  AssemblyCode *code = new AssemblyCode;
  code->initWithAddressRange((void *)address, size);
  return code;
}

AssemblyCode *AssemblyCode::FinalizeFromTruboAssember(AssemblerBase *assembler) {
  TurboAssembler *turbo_assembler = reinterpret_cast<TurboAssembler *>(assembler);
  int code_size                   = turbo_assembler->CodeSize();

// Allocate the executable memory
#if TARGET_ARCH_ARM64 || TARGET_ARCH_ARM
  // extra bytes for align needed
  MemoryRegion *code_region = CodeChunk::AllocateCode(code_size + 4);
#else
  MemoryRegion *code_region = ExecutableMemoryArena::AllocateCodeChunk(code_size);
#endif

  void *code_address = code_region->pointer();
  // Realize(Relocate) the buffer_code to the executable_memory_address, remove the ExternalLabels, etc, the pc-relative instructions
  turbo_assembler->CommitRealize(code_address);
  CodeChunk::PatchCodeBuffer(turbo_assembler->ReleaseAddress(), turbo_assembler->GetCodeBuffer());
  Code *code = turbo_assembler->GetCode();
  DLOG("[*] AssemblyCode finalize assembler at %p\n", code->raw_instruction_start());
  return reinterpret_cast<AssemblyCode *>(code);
}

} // namespace zz
