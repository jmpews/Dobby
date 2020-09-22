#include "./AssemblyCode.h"

#include "dobby_internal.h"

#include "PlatformUnifiedInterface/ExecMemory/CodePatchTool.h"

AssemblyCode *AssemblyCode::FinalizeFromAddress(addr_t address, int size) {
  AssemblyCode *result = NULL;
  result               = new AssemblyCode;
  result->initWithAddressRange(address, size);
  return result;
}

AssemblyCode *AssemblyCode::FinalizeFromTurboAssember(AssemblerBase *assembler) {
#if 0
  TurboAssembler *turboAssembler = reinterpret_cast<TurboAssembler *>(assembler);
#endif
  AssemblyCode *result = NULL;

  CodeBufferBase *codeBuffer = reinterpret_cast<CodeBufferBase *>(assembler->GetCodeBuffer());

  void *address = assembler->GetRealizeAddress();
  if (!address) {

    int buffer_size = 0;
    {
      buffer_size = codeBuffer->getSize();
#if TARGET_ARCH_ARM64 || TARGET_ARCH_ARM
      // FIXME: need it ? actually ???
      // extra bytes for align needed
      buffer_size += 4;
#endif
    }

    // assembler without specific memory address
    AssemblyCodeChunk *codeChunk;
    codeChunk = MemoryArena::AllocateCodeChunk(buffer_size);
    if (codeChunk == nullptr)
      return nullptr;

    address = codeChunk->address;
    assembler->CommitRealizeAddress(codeChunk->address);
    delete codeChunk;
  }

  // Realize(Relocate) the buffer_code to the executable_memory_address, remove the ExternalLabels, etc, the pc-relative instructions
  CodePatch(address, codeBuffer->getRawBuffer(), codeBuffer->getSize());

  result = FinalizeFromAddress((addr_t)address, codeBuffer->getSize());
  DLOG("Finalize assembler at %p", (void *)address);

  return result;
}

#if 0
AssemblyCode *AssemblyCode::FinalizeFromCodeBuffer(void *address, CodeBufferBase *codeBuffer) {
  // Realize(Relocate) the buffer_code to the executable_memory_address, remove the ExternalLabels, etc, the pc-relative
  // instructions
  CodePatch(address, codeBuffer->getRawBuffer(), codeBuffer->getSize());

  // Alloc a new AssemblyCode
  AssemblyCode *code = new AssemblyCode;
  code->initWithAddressRange((addr_t)address, codeBuffer->getSize());
  return code;
}
#endif

void AssemblyCode::initWithAddressRange(addr_t address, int size) {
  range_.address = (void *)address;
  range_.length  = size;
}

void AssemblyCode::reInitWithAddressRange(addr_t address, int size) {
  this->initWithAddressRange(address, size);
}