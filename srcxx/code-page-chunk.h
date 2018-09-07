#ifndef HOOKZZ_CODE_PAGE_CHUNK_H_
#define HOOKZZ_CODE_PAGE_CHUNK_H_

#include "vm_core/modules/assembler/assembler.h"

class CodeChunk : public MemoryChunk {
public:
  enum MemoryOperationError { kNotSupportAllocateExecutableMemory, kNotEnough, kNone };

  MemoryOperationError Patch(void *address, void *buffer, int size);

  static MemoryOperationError Patch(void *page_address, int offset, void *buffer, int size);

  void *FinalizeAssembler(Assembler *assembler);

private:
  std::vector<CodeChunk *> code_pages_;
}

#endif // !1