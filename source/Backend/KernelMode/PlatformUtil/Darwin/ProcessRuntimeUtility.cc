#include "dobby_internal.h"

#include "PlatformUtil/ProcessRuntimeUtility.h"

static bool memory_region_comparator(MemRegion a, MemRegion b) {
  return (a.mem.begin < b.mem.begin);
}

std::vector<MemRegion> ProcessRuntimeUtility::GetProcessMemoryLayout() {
  std::vector<MemRegion> ProcessMemoryLayout;

  return ProcessMemoryLayout;
}

std::vector<RuntimeModule> ProcessRuntimeUtility::GetProcessModuleMap() {
  std::vector<RuntimeModule> ProcessModuleMap;

  return ProcessModuleMap;
}

RuntimeModule ProcessRuntimeUtility::GetProcessModule(const char *name) {
  std::vector<RuntimeModule> ProcessModuleMap = GetProcessModuleMap();
  return RuntimeModule{0};
}
