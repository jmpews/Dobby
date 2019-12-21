#ifndef UNIFIED_INTERFACE_STD_MEMORY_H
#define UNIFIED_INTERFACE_STD_MEMORY_H

enum MemoryPermission { kNoAccess, kRead, kReadWrite, kReadWriteExecute, kReadExecute };

typedef enum _MemoryOperationError {
  kMemoryOperationSuccess,
  kMemoryOperationError,
  kNotSupportAllocateExecutableMemory,
  kNotEnough,
  kNone
} MemoryOperationError;

#endif
