#pragma once

#include "PlatformUnifiedInterface/MemoryAllocator.h"

#include "UnifiedInterface/platform.h"

#include <vector>
#include <algorithm>

typedef struct _RuntimeModule {
  char path[1024];
  void *load_address;
} RuntimeModule;

typedef struct {
  MemRange mem;
  MemoryPermission permission;
} MemRegion;

class ProcessRuntimeUtility {
public:
  static std::vector<MemRegion> GetProcessMemoryLayout();

  static std::vector<RuntimeModule> GetProcessModuleMap();

  static RuntimeModule GetProcessModule(const char *name);
};