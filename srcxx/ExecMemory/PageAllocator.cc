
#include "PageAllocator.h"

static void *PageAllocator::Allocate(MemoryPermission permission) {
  int page_size = OSMemory::PageSize();
  void *page    = OSMemory::Allocate(0, page_size, 0, permission);
  return page;
}

static size_t PageAllocator::PageSize() {
  int page_size = OSMemory::PageSize();
  return page_size;
}

static bool PageAllocator::SetPermissions(void *address, size_t size, MemoryPermission access) {
  return OSMemory::SetPermissions(address, size, access);
}