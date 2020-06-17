#include "AssemblyCode.h"
#include "ExecutableMemoryArena.h"
#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "logging/check_logging.h"

namespace zz {

AssemblyCode *AssemblyCode::FinalizeFromAddress(addr_t address, int size) {
  AssemblyCode *code = new AssemblyCode;
  code->initWithAddressRange(address, size);
  return code;
}

AssemblyCode *AssemblyCode::FinalizeFromTurboAssember(AssemblerBase *assembler) {
#if 0
  TurboAssembler *turboAssembler = reinterpret_cast<TurboAssembler *>(assembler);
#endif

  CodeBufferBase *codeBuffer = reinterpret_cast<CodeBufferBase *>(assembler->GetCodeBuffer());
  int buffer_size            = codeBuffer->getSize();

// Allocate the executable memory
#if TARGET_ARCH_ARM64 || TARGET_ARCH_ARM
  // extra bytes for align needed
  buffer_size += 4;
#endif

  void *address = assembler->GetRealizeAddress();
  if (!address) {
    // assembler without specific memory address
    AssemblyCodeChunk *codeChunk = ExecutableMemoryArena::AllocateCodeChunk(buffer_size);
    address                      = codeChunk->address;
    assembler->CommitRealizeAddress(codeChunk->address);
    delete codeChunk;
  }

  AssemblyCode *code = FinalizeFromCodeBuffer(address, reinterpret_cast<CodeBufferBase *>(assembler->GetCodeBuffer()));
  DLOG("AssemblyCode finalize assembler at %p\n", (void *)code->raw_instruction_start());

  return reinterpret_cast<AssemblyCode *>(code);
}

AssemblyCode *AssemblyCode::FinalizeFromCodeBuffer(void *address, CodeBufferBase *codeBuffer) {
  // Realize(Relocate) the buffer_code to the executable_memory_address, remove the ExternalLabels, etc, the pc-relative
  // instructions
  CodePatch(address, codeBuffer->getRawBuffer(), codeBuffer->getSize());

  // Alloc a new AssemblyCode
  AssemblyCode *code = new AssemblyCode;
  code->initWithAddressRange((addr_t)address, codeBuffer->getSize());
  return code;
}

void AssemblyCode::initWithAddressRange(addr_t address, int size) {
  address_ = (addr_t)address;
  size_    = size;
}

} // namespace zz
