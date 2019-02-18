#ifndef HOOKZZ_CODE_PAGE_CHUNK_H_
#define HOOKZZ_CODE_PAGE_CHUNK_H_

#include "stdcxx/LiteMutableArray.h"

typedef struct {
  void *address;
  int size;
} AssemblyCodeChunk, WritableDataChunk;

typedef struct {
  void *address;
  void *cursor;
  int capacity;
  union {
  LiteMutableArray *data_chunks;
  LiteMutableArray *code_chunks;
  };
} ExecutablePage, WritablePage;

class ExecutableMemoryArena {
public:
    static AssemblyCodeChunk *AllocateCodeChunk(int inSize);

    static void Destory(AssemblyCodeChunk *codeChunk);

private:
  static LiteMutableArray *page_chunks;
};

#endif
