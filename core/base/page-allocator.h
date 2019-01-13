#ifndef BASE_PAGE_ALLOCATOR_H_
#define BASE_PAGE_ALLOCATOR_H_

#include "vm_core/macros.h"
#include "vm_core/platform/platform.h"

namespace zz {

class PageAllocator {
public:
  static void *Allocate(OSMemory::MemoryPermission permission) {
    int page_size = OSMemory::PageSize();
    void *page    = OSMemory::Allocate(0, page_size, 0, permission);
    return page;
  }

  static size_t PageSize() { return OSMemory::PageSize(); }
  static bool SetPermissions(void *address, size_t size, OSMemory::MemoryPermission access) {
    return OSMemory::SetPermissions(address, size, access);
  }
};

} // namespace zz

#endif