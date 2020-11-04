
#ifndef NEAR_EXECUTABLE_MEMORY_ARENA_H
#define NEAR_EXECUTABLE_MEMORY_ARENA_H

#include "MemoryKit/MemoryArena.h"

class NearMemoryArena : public MemoryArena {
public:
  static MemoryChunk *AllocateChunk(addr_t position, size_t alloc_range, int alloc_size, MemoryPermission permission);

  static WritableDataChunk *AllocateDataChunk(addr_t position, size_t alloc_range, int alloc_size);

  static AssemblyCodeChunk *AllocateCodeChunk(addr_t position, size_t alloc_range, int alloc_size);

  static int PushPage(addr_t page_addr, MemoryPermission permission);

  static void Destroy(MemoryChunk *chunk);

private:
  static LiteMutableArray *page_chunks;
};

#endif
