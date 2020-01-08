
#ifndef NEAR_EXECUTABLE_MEMORY_ARENA_H
#define NEAR_EXECUTABLE_MEMORY_ARENA_H

#include "ExecMemory/ExecutableMemoryArena.h"

class NearExecutableMemoryArena : public ExecutableMemoryArena {
public:
  static AssemblyCodeChunk *AllocateCodeChunk(int inSize);

  static void Destory(AssemblyCodeChunk *codeChunk);

private:
  static LiteMutableArray *page_chunks;
};

#endif