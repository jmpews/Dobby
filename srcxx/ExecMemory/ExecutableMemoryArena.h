#ifndef HOOKZZ_CODE_PAGE_CHUNK_H_
#define HOOKZZ_CODE_PAGE_CHUNK_H_

#include "stdcxx/LiteMutableArray.h"

struct AssemblyCodeChunk {
  void *address;
  int size;
};

struct ExecutablePage {
  void *address;
  void *cursor;
  int capacity;
  LiteMutableArray code_chunks;
};

class ExecutableMemoryArena {
public:
    static AssemblyCodeChunk *AllocateCodeChunk(int inSize);

private:
  static LiteMutableArray page_chunks;
};

#endif