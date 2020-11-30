#include "./AssemblyCodeBuilder.h"

#include "dobby_internal.h"

#include "PlatformUnifiedInterface/ExecMemory/CodePatchTool.h"

AssemblyCodeChunk *AssemblyCodeBuilder::FinalizeFromAddress(addr_t address, int size) {
  AssemblyCodeChunk *result = NULL;
  result                    = new AssemblyCodeChunk;
  result->init_region_range(address, size);
  return result;
}

AssemblyCodeChunk *AssemblyCodeBuilder::FinalizeFromTurboAssembler(AssemblerBase *assembler) {
  CodeBufferBase *codeBuffer = reinterpret_cast<CodeBufferBase *>(assembler->GetCodeBuffer());

  void *address = assembler->RealizeAddress();
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
    AssemblyCodeChunk *cchunk;
    cchunk = MemoryArena::AllocateCodeChunk(buffer_size);
    if (cchunk == nullptr)
      return nullptr;

    address = cchunk->address;
    assembler->CommitRealizeAddress(cchunk->address);
    delete cchunk;
  }

  // Realize(Relocate) the buffer_code to the executable_memory_address, remove the ExternalLabels, etc, the pc-relative
  // instructions
  CodePatch(address, codeBuffer->getRawBuffer(), codeBuffer->getSize());

  AssemblyCodeChunk *result = NULL;
  result                    = FinalizeFromAddress((addr_t)address, codeBuffer->getSize());
  DLOG(0, "[assembler] Finalize assembler at %p", (void *)address);

  return result;
}