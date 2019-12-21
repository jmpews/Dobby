#include "PlatformInterface/Common/Platform.h"

#include "ExtraInternalPlugin/NearBranchTrampoline/PlatformUtil/GetProcessMemoryLayout.h"

#include "ExecMemory/ExecutableMemoryArena.h"

using namespace zz;

AssemblyCodeChunk *SearchCodeChunk(addr_t start, addr_t end, int inSize) {
  std::vector<MemoryRegion> memory_layout = GetProcessMemoryLayout();
  return NULL;
}

#if 0
// Search code cave from MemoryLayout
AssemblyCodeChunk *SearchCodeCave(int size, uintptr_t pos, int range_size) {
  std::vector<MemoryRegion> memory_layout = GetProcessMemoryLayout();
  // initialize needed variable
  char *dummy_0 = (char *)malloc(size);
  memset(dummy_0, 0, size);
  uintptr_t limit_start  = pos - range_size;
  uintptr_t limit_end    = pos + range_size;
  uintptr_t search_start = 0, search_end = 0;

  auto it = memory_layout.begin();
  for (; it != memory_layout.end(); it++) {
    if ((*it).permission != MemoryPermission::kReadExecute)
      continue;

    if (limit_start > (*it).end)
      continue;
    if (limit_end < (*it).start)
      continue;

    search_start = limit_start > (*it).start ? limit_start : (*it).start;
    search_end   = limit_end < (*it).end ? limit_end : (*it).end;
    search_start = ALIGN_CEIL(search_start, 4);
    search_end   = ALIGN_FLOOR(search_end, 4);
    size         = ALIGN_CEIL(size, 4);
    for (uintptr_t i = search_start; i < (search_end - size); i += 4) {
      if (memcmp((void *)i, dummy_0, size) == 0) {
        AssemblyCodeChunk *codeChunk = new AssemblyCodeChunk;
        codeChunk->address           = (void *)i;
        codeChunk->size              = size;
        return codeChunk;
      }
    }
  }
  return NULL;
}
#endif