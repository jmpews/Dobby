#ifndef HOOKZZ_CODE_PAGE_CHUNK_H_
#define HOOKZZ_CODE_PAGE_CHUNK_H_

#include "srcxx/LiteMutableArray.h"

using namespace zz;

class ExecutableMemoryArena {
public:
  static void *AllocateCodeChunk(int *actual_size);

  static void *SearchCodeCave(uintptr_t pos, int range_size, int *actual_size);

private:
  static LiteMutableArray page_chunks;
};

#endif