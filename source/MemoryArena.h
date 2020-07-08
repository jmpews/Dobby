#ifndef EXECUTABLE_MEMORY_ARENA_H
#define EXECUTABLE_MEMORY_ARENA_H

#include "dobby_internal.h"

#include "PlatformUnifiedInterface/StdMemory.h"

typedef MemoryRange MemoryChunk;
typedef MemoryChunk AssemblyCodeChunk, WritableDataChunk;

typedef struct {
  void *address;
  void *cursor;
  size_t capacity;
  union {
    LiteMutableArray *data_chunks;
    LiteMutableArray *code_chunks;
  };
} ExecutablePage, WritablePage;

class MemoryArena {
public:
  static AssemblyCodeChunk *AllocateCodeChunk(int inSize);

  static void Destory(AssemblyCodeChunk *codeChunk);

public:
  static LiteMutableArray *page_chunks;
};

#endif
