#pragma once

#include "MemoryAllocator/MemoryAllocator.h"
#include "PlatformUnifiedInterface/platform.h"

struct RuntimeModule {
  void *base;
  char path[1024];
};

#define MEM_PERM_R 0x1
#define MEM_PERM_W 0x2
#define MEM_PERM_X 0x4
struct MemRegion : MemRange {
  int perm;

  MemRegion(addr_t addr, size_t size, int perm) : MemRange(addr, size), perm(perm) {
  }
};

class ProcessRuntime {
public:
  static const stl::vector<MemRegion> &getMemoryLayout();

  static const stl::vector<RuntimeModule> &getModuleMap();

  static RuntimeModule getModule(const char *name);
};