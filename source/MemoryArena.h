#ifndef EXECUTABLE_MEMORY_ARENA_H
#define EXECUTABLE_MEMORY_ARENA_H

#include "dobby_internal.h"

#include "PlatformUnifiedInterface/StdMemory.h"

typedef MemoryRange MemoryChunk;
typedef MemoryChunk AssemblyCodeChunk, WritableDataChunk;

typedef struct {
  MemoryChunk page;
  addr_t page_cursor;
  MemoryPermission permission;
  LiteMutableArray *chunks;
} PageChunk;

class MemoryArena {
public:

  static MemoryChunk *AllocateChunk(int inSize, MemoryPermission permission);

  static WritableDataChunk *AllocateDataChunk(int inSize);

  static AssemblyCodeChunk *AllocateCodeChunk(int inSize);

  static void Destory(MemoryChunk *chunk);

public:
  static LiteMutableArray *page_chunks;
};

#endif
