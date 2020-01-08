
#include "ExecMemory/PageAllocator.h"

#include "PlatformInterface/Common/Platform.h"

using namespace zz;

void *PageAllocator::Allocate(MemoryPermission permission) {

  AssemblyCodeChunk *SearchNearRelativeCodeChunk(int size, uintptr_t pos, int range_size) {
    std::vector<MemoryRegion> *memory_layout = GetProcessMemoryLayout();

    auto it = memory_layout.begin();
    for (; it != memory_layout.end(); it++) {
      if ((*it).permission != MemoryPermission::kReadExecute)
        continue;
    }

    int page_size = OSMemory::PageSize();
    void *page    = OSMemory::Allocate(0, page_size, permission);
    return page;
  }

  int PageAllocator::PageSize() {
    return OSMemory::PageSize();
  }

  bool PageAllocator::SetPermissions(void *address, MemoryPermission access) {
    return OSMemory::SetPermissions(address, OSMemory::PageSize(), access);
  }