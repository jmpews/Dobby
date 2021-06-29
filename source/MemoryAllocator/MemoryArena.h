#ifndef MemoryAllocator_MemoryArena_h
#define MemoryAllocator_MemoryArena_h

#include "PlatformUnifiedInterface/StdMemory.h"

struct MemoryChunk : MemoryRange {
  inline void copy(MemoryChunk *chunk) {
    address = chunk->address;
    length = chunk->length;
  }

  inline addr_t start() {
    return (addr_t)address;
  };

  inline size_t size() {
    return length;
  };
};

typedef MemoryChunk AssemblyCodeChunk, WritableDataChunk;

typedef struct {
  MemoryChunk mem;
  addr_t cursor;
  MemoryPermission permission;
  std::vector<MemoryChunk *> chunks;
} PageChunk;

class MemoryArena {
public:
  static MemoryChunk *AllocateChunk(int alloc_size, MemoryPermission permission);

  static WritableDataChunk *AllocateDataChunk(int alloc_size);

  static AssemblyCodeChunk *AllocateCodeChunk(int alloc_size);

  static void Destroy(MemoryChunk *chunk);

public:
  static std::vector<PageChunk *> page_chunks;
};

#endif
