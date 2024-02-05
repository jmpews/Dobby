#include "PlatformUtil/ProcessRuntime.h"

#include <vector>

#include <windows.h>

#define LINE_MAX 2048

static bool memory_region_comparator(MemRange a, MemRange b) {
  return (a.address > b.address);
}

// https://gist.github.com/jedwardsol/9d4fe1fd806043a5767affbd200088ca

stl::vector<MemRange> ProcessMemoryLayout;
stl::vector<MemRange> ProcessRuntime::getMemoryLayout() {
  if (!ProcessMemoryLayout.empty()) {
    ProcessMemoryLayout.clear();
  }

  char *address{nullptr};
  MEMORY_BASIC_INFORMATION region;

  while (VirtualQuery(address, &region, sizeof(region))) {
    address += region.RegionSize;
    if (!(region.State & (MEM_COMMIT | MEM_RESERVE))) {
      continue;
    }

    MemoryPermission permission = MemoryPermission::kNoAccess;
    auto mask = PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;
    switch (region.Protect & ~mask) {
    case PAGE_NOACCESS:
    case PAGE_READONLY:
      break;

    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
      permission = MemoryPermission::kReadExecute;
      break;

    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
      permission = MemoryPermission::kReadWrite;
      break;

    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      permission = MemoryPermission::kReadWriteExecute;
      break;
    }

    ProcessMemoryLayout.push_back(MemRange{(void *)region.BaseAddress, region.RegionSize, permission});
  }
  return ProcessMemoryLayout;
}

stl::vector<RuntimeModule> ProcessModuleMap;

stl::vector<RuntimeModule> ProcessRuntime::getModuleMap() {
  if (!ProcessMemoryLayout.empty()) {
    ProcessMemoryLayout.clear();
  }
  return ProcessModuleMap;
}

RuntimeModule ProcessRuntime::getModule(const char *name) {
  stl::vector<RuntimeModule> ProcessModuleMap = getModuleMap();
  for (auto module : ProcessModuleMap) {
    if (strstr(module.path, name) != 0) {
      return module;
    }
  }
  return RuntimeModule{0};
}