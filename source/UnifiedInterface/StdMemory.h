#ifndef UNIFIED_INTERFACE_STD_MEMORY_H
#define UNIFIED_INTERFACE_STD_MEMORY_H

#include "Common/headers/common_header.h"

enum MemoryPermission { kNoAccess, kRead, kReadWrite, kReadWriteExecute, kReadExecute };

typedef enum _MemoryOperationError {
  kMemoryOperationSuccess,
  kMemoryOperationError,
  kNotSupportAllocateExecutableMemory,
  kNotEnough,
  kNone
} MemoryOperationError;

#endif
