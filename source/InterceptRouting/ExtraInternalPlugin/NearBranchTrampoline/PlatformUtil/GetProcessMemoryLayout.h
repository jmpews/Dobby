#ifndef GET_PROCESS_MEMORY_LAYOUT_H
#define GET_PROCESS_MEMORY_LAYOUT_H

#include "PlatformUnifiedInterface/StdMemory.h"

#include <vector>
#include <algorithm>

std::vector<MemoryRegion> GetProcessMemoryLayout();

#endif