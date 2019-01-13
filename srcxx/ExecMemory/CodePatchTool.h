
#ifndef ZZ_CODE_PATCH_TOOL_H_
#define ZZ_CODE_PATCH_TOOL_H_

typedef enum _MemoryOperationError {
  kMemoryOperationSuccess,
  kMemoryOperationError,
  kNotSupportAllocateExecutableMemory,
  kNotEnough,
  kNone
} MemoryOperationError;

static MemoryOperationError Patch(void *address, void *buffer, int size);

static MemoryOperationError Patch(void *page_address, int offset, void *buffer, int size);

static MemoryOperationError PatchCodeBuffer(void *page_address, zz::CodeBuffer *buffer);

#endif