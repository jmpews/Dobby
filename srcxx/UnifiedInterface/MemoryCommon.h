
#ifndef STD_MEM_MEMORY_REGION_H
#define STD_MEM_MEMORY_REGION_H

#include "UnifiedInterface/StdMemory.h"
// "the same attribute memory region, such as __TEXT segment"

struct MemoryRange {
  uintptr_t address;
  size_t length;
};

struct MemoryRegion {
  uintptr_t address;
  size_t length;
  MemoryPermission permission;
};

struct MemoryPage {
  uintptr_t address;
  MemoryPermission permission;
};

#endif // MEM_MEMORY_REGION_H