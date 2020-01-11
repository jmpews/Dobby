
#ifndef STD_MEM_MEMORY_REGION_H
#define STD_MEM_MEMORY_REGION_H

#include "UnifiedInterface/StdMemory.h"
// "the same attribute memory region, such as __TEXT segment"

typedef struct MemoryRange {
  uintptr_t address;
  size_t length;
} MemoryRange;

typedef struct MemoryRegion {
  uintptr_t address;
  size_t length;
  MemoryPermission permission;
} MemoryRegion;

typedef struct MemoryPage {
  uintptr_t address;
  MemoryPermission permission;
} MemoryPage;

#endif // MEM_MEMORY_REGION_H