#pragma once

#include "PlatformUnifiedInterface/StdMemory.h"

#include <vector>
#include <algorithm>

typedef struct _RuntimeModule {
  char path[1024];
  void *load_address;
} RuntimeModule;

class ProcessRuntimeUtility {
public:
  static std::vector<MemoryRegion> GetProcessMemoryLayout();

  static std::vector<RuntimeModule> GetProcessModuleMap();

  static RuntimeModule GetProcessModule(const char *name);
};