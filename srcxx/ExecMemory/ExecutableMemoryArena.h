#ifndef HOOKZZ_CODE_PAGE_CHUNK_H_
#define HOOKZZ_CODE_PAGE_CHUNK_H_

#include "LiteMutableArray.h"

using namespace zz;

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
  static void *AllocateCodeChunk(AssemblyCodeChunk *codeChunk);

private:
  static LiteMutableArray page_chunks;
};

#endif