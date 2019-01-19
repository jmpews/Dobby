
#include "ExecMemory/PageAllocator.h"

#include "PlatformInterface/platform.h"

using namespace zz;

void *PageAllocator::Allocate(MemoryPermission permission) {
  int page_size = OSMemory::PageSize();
  void *page    = OSMemory::Allocate(0, page_size, permission);
  return page;
}

 size_t PageAllocator::PageSize() { return OSMemory::PageSize(); }

 bool PageAllocator::SetPermissions(void *address, MemoryPermission access) {
  return OSMemory::SetPermissions(address, OSMemory::PageSize(), access);
}