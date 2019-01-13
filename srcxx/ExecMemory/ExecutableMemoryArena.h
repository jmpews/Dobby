#ifndef HOOKZZ_CODE_PAGE_CHUNK_H_
#define HOOKZZ_CODE_PAGE_CHUNK_H_

#include "srcxx/LiteMutableArray.h"

using namespace zz;

class ExecutableMemoryArena {
public:
  static void *AllocateCodeChunk(int *actual_size);

  static void *SearchCodeCave(uintptr_t pos, int range_size, int *actual_size);

private:
  static LiteMutableArray pages;
};

class CodeChunk : public MemoryChunk {
public:
  typedef enum _MemoryOperationError {
    kMemoryOperationSuccess,
    kMemoryOperationError,
    kNotSupportAllocateExecutableMemory,
    kNotEnough,
    kNone
  } MemoryOperationError;

  CodeChunk(void *address, size_t size) : MemoryChunk(address, size){};

  static MemoryRegion *AllocateCodeBlock(size_t size);

  static CodeChunk *AllocateCodePage();

  static MemoryRegion *AllocateCodeCave(uword pos, uword range_size, size_t size);

  static MemoryOperationError Patch(void *address, void *buffer, int size);

  static MemoryOperationError Patch(void *page_address, int offset, void *buffer, int size);

  static MemoryOperationError PatchCodeBuffer(void *page_address, zz::CodeBuffer *buffer);

private:
  static std::vector<CodeChunk *> code_pages_;
};

#endif