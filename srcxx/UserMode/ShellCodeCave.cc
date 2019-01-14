
#include "ShellCodeCave.h"

// Search code cave from MemoryLayout
AssemblyCodeChunk *SearchCodeCave(int size, uintptr_t pos, int range_size) {
  std::vector<OSMemory::MemoryRegion> memory_layout = OSMemory::GetMemoryLayout();
  // initialize needed variable
  char *dummy_0 = (char *)malloc(size);
  memset(dummy_0, 0, size);
  uintptr_t limit_start  = pos - range_size;
  uintptr_t limit_end    = pos + range_size;
  uintptr_t search_start = 0, search_end = 0;

  auto it = memory_layout.begin();
  for (; it != memory_layout.end(); it++) {
    if ((*it).permission != OSMemory::MemoryPermission::kReadExecute)
      continue;

    if (limit_start > (*it).end)
      continue;
    if (limit_end < (*it).start)
      continue;

    search_start = limit_start > (*it).start ? limit_start : (*it).start;
    search_end   = limit_end < (*it).end ? limit_end : (*it).end;
#if defined(__arm__) || defined(__arm64__) || defined(__aarch64__)
    search_start = ALIGN_CEIL(search_start, 4);
    search_end   = ALIGN_FLOOR(search_end, 4);
    size         = ALIGN_CEIL(size, 4);
    for (uintptr_t i = search_start; i < (search_end - size); i += 4) {
      if (memcmp((void *)i, dummy_0, size) == 0) {
        return new MemoryRegion((void *)i, size);
      }
    }
#else
#error "Unsupported x86/x86_64 architecture""
#endif
  }
  return NULL;
}