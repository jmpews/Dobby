
#include "PageAllocator.h"

static void *PageAllocator::Allocate(MemoryPermission permission) {
  int page_size = OSMemory::PageSize();
  void *page    = OSMemory::AllocatePage(0, page_size, 0, permission);
  return page;
}

static size_t PageAllocator::PageSize() { return OSMemory::PageSize(); }

static bool PageAllocator::SetPermissions(void *address, MemoryPermission access) {
  return OSMemory::SetPermissions(address, access);
}