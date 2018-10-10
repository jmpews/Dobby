#ifndef ZZ_BASE_PAGE_ALLOCATOR_H_
#define ZZ_BASE_PAGE_ALLOCATOR_H_

#include "vm_core/macros.h"
#include "vm_core/platform/platform.h"

namespace zz {

class PageAllocator {
public:
  static void *Allocate(OS::MemoryPermission permission) {
    int page_size = OS::PageSize();
    void *page    = OS::Allocate(0, page_size, 0, permission);
    return page;
  }

  static size_t PageSize() {
    return OS::PageSize();
  }
  static bool SetPermissions(void *address, size_t size, OS::MemoryPermission access) {
    return OS::SetPermissions(address, size, access);
  }
};

} // namespace zz

#endif