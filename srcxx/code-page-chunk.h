#ifndef HOOKZZ_CODE_PAGE_CHUNK_H_
#define HOOKZZ_CODE_PAGE_CHUNK_H_

class CodePageChunk : public MemoryChunk {
public:
  enum MemoryOperationError { kNotSupportAllocateExecutableMemory, kNotEnough, kNone };

  MemoryOperationError Patch(void *address, void *buffer, int size);

  static MemoryOperationError Patch(void *page_address, int offset, void *buffer, int size);

private:
  std::vector<CodePageChunk *> code_pages_;
}

#endif // !1