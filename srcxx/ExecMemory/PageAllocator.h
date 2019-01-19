#ifndef BASE_PAGE_ALLOCATOR_H_
#define BASE_PAGE_ALLOCATOR_H_

#include "PlatformInterface/platform.h"

namespace zz {

class PageAllocator {
public:
  static void *Allocate(MemoryPermission permission);

  static size_t PageSize();

  static bool SetPermissions(void *address, MemoryPermission access);
};

} // namespace zz

#endif