#include "MemoryAllocator/AssemblyCodeBuilder.h"

#include "dobby_internal.h"
#include "PlatformUnifiedInterface/ExecMemory/CodePatchTool.h"

AssemblyCodeChunk *AssemblyCodeBuilder::FinalizeFromAddress(addr_t chunk_addr, size_t chunk_size) {
  AssemblyCodeChunk *result = nullptr;
  result = new AssemblyCodeChunk;
  result->address = (void *)chunk_addr;
  result->length = chunk_size;
  return result;
}

AssemblyCodeChunk *AssemblyCodeBuilder::FinalizeFromTurboAssembler(AssemblerBase *assembler) {
  AssemblyCodeChunk *result = nullptr;

  CodeBufferBase *buffer = nullptr;
  buffer = (CodeBufferBase *)assembler->GetCodeBuffer();

  void *realized_addr = assembler->GetRealizedAddress();
  if (realized_addr == nullptr) {
    int buffer_size = 0;
    {
      buffer_size = buffer->GetBufferSize();
#if TARGET_ARCH_ARM
      // extra bytes for align needed
      buffer_size += 4;
#endif
    }

    // assembler without specific memory address
    result = MemoryArena::AllocateCodeChunk(buffer_size);
    if (result == nullptr)
      return nullptr;

    realized_addr = result->address;
    assembler->SetRealizedAddress(realized_addr);
  } else {
    result = AssemblyCodeBuilder::FinalizeFromAddress((addr_t)realized_addr, buffer->GetBufferSize());
  }

  // Realize(Relocate) the buffer_code to the executable_memory_address, remove the ExternalLabels, etc, the pc-relative
  // instructions
  CodePatch(realized_addr, buffer->GetBuffer(), buffer->GetBufferSize());

  return result;
}