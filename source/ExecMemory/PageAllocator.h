#ifndef EXECUTABLE_MEMORY_PAGE_ALLOCATOR_H
#define EXECUTABLE_MEMORY_PAGE_ALLOCATOR_H

#include "PlatformInterface/Common/Platform.h"

class PageAllocator {
public:
  static void *Allocate(MemoryPermission permission);

  static int PageSize();

  static bool SetPermissions(void *address, MemoryPermission access);
};

#endif