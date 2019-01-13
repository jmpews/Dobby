
#ifndef STD_MEM_MEMORY_REGION_H
#define STD_MEM_MEMORY_REGION_H

// "the same attribute memory region, such as __TEXT segment"

enum MemoryPermission { kNoAccess, kRead, kReadWrite, kReadWriteExecute, kReadExecute };

struct MemoryRange {
  uinptr_t address;
  size_t length;
};

struct MemoryRegion {
  uintptr_t address;
  size_t length;
  MemoryPermission permission;
};

struct MemoryPage {
  uinptr_t address;
  MemoryPermission permission;
};

#endif // MEM_MEMORY_REGION_H