#ifndef MemoryAllocator_AssemblyCodeBuilder_h
#define MemoryAllocator_AssemblyCodeBuilder_h

#include "MemoryAllocator/MemoryArena.h"

#include "core/assembler/assembler.h"

using namespace zz;

class AssemblyCodeBuilder {
public:
  // realize the buffer address to runtime code, and create a corresponding Code Object
  static AssemblyCodeChunk *FinalizeFromAddress(addr_t chunk_addr, size_t chunk_size);

  // realize the buffer address to runtime code, and create a corresponding Code Object
  static AssemblyCodeChunk *FinalizeFromTurboAssembler(AssemblerBase *assembler);
};

#endif
