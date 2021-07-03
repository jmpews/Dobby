#include "MemoryAllocator/AssemblyCodeBuilder.h"

#include "dobby_internal.h"
#include "PlatformUnifiedInterface/ExecMemory/CodePatchTool.h"

AssemblyCode *AssemblyCodeBuilder::FinalizeFromTurboAssembler(AssemblerBase *assembler) {
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

    auto *block = CodeMemoryArena::SharedInstance()->allocCodeBlock(buffer_size);
    if (block == nullptr)
      return nullptr;

    realized_addr = (void *)block->addr;
    assembler->SetRealizedAddress(realized_addr);
  }

  // Realize the buffer code to the executable memory address, remove the ExternalLabel, etc, the pc-relative
  // instructions
  CodePatch(realized_addr, buffer->GetBuffer(), buffer->GetBufferSize());

  AssemblyCode *code = new AssemblyCode{.begin = realized_addr, .size = buffer->GetBufferSize()};
  return code;
}