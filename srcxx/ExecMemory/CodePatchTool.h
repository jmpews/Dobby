
#ifndef ZZ_CODE_PATCH_TOOL_H_
#define ZZ_CODE_PATCH_TOOL_H_

#include "UserMode/CodeBufferBase.h"

typedef enum _MemoryOperationError {
  kMemoryOperationSuccess,
  kMemoryOperationError,
  kNotSupportAllocateExecutableMemory,
  kNotEnough,
  kNone
} MemoryOperationError;


class CodePatchTool {
public:
    static MemoryOperationError Patch(void *address, void *buffer, int size);

    static MemoryOperationError Patch(void *page_address, int offset, void *buffer, int size);

    static MemoryOperationError PatchCodeBuffer(void *page_address, CodeBufferBase *buffer);
};

#endif