#ifndef HOOKZZ_CODE_PAGE_CHUNK_H_
#define HOOKZZ_CODE_PAGE_CHUNK_H_

#include "vm_core/modules/assembler/assembler.h"
#include "vm_core/base/code-buffer.h"
#include "vm_core/base/memory-chunk.h"
#include "vm_core/base/page-allocator.h"

using namespace zz;

class CodeChunk : public zz::MemoryChunk {
public:
  typedef enum _MemoryOperationError {
    kMemoryOperationSuccess,
    kMemoryOperationError,
    kNotSupportAllocateExecutableMemory,
    kNotEnough,
    kNone
  } MemoryOperationError;

  CodeChunk(void *address, size_t size) : MemoryChunk(address, size){};

  static zz::MemoryRegion *AllocateCode(size_t size);

  static CodeChunk *AllocateCodePage();

  static zz::MemoryRegion *AllocateCodeCave(uword pos, uword range_size, size_t size);

  static MemoryOperationError Patch(void *address, void *buffer, int size);

  static MemoryOperationError Patch(void *page_address, int offset, void *buffer, int size);

  static MemoryOperationError PatchCodeBuffer(void *page_address, zz::CodeBuffer *buffer);

private:
  static std::vector<CodeChunk *> code_pages_;
};

#endif