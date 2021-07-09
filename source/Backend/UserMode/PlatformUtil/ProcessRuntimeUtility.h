#pragma once

#include "PlatformUnifiedInterface/MemoryAllocator.h"

#include "UnifiedInterface/platform.h"

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
  static const std::vector<MemRegion> &GetProcessMemoryLayout();

  static const std::vector<RuntimeModule> *GetProcessModuleMap();

  static RuntimeModule GetProcessModule(const char *name);
};