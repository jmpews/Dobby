
#ifndef NEAR_EXECUTABLE_MEMORY_ARENA_H
#define NEAR_EXECUTABLE_MEMORY_ARENA_H

#include "MemoryArena.h"

class NearMemoryArena : public MemoryArena {
public:
  static MemoryChunk *AllocateChunk(addr_t position, size_t range, int inSize, MemoryPermission permission);

  static WritableDataChunk *AllocateDataChunk(addr_t position, size_t range, int inSize);

  static AssemblyCodeChunk *AllocateCodeChunk(addr_t position, size_t range, int inSize);

  static int PushMostNearPage(addr_t position, size_t range, MemoryPermission permission);

  static void Destory(MemoryChunk *chunk);

private:
  static LiteMutableArray *page_chunks;
};

#endif
