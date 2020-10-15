#include "dobby_internal.h"

#include <dlfcn.h>
#include <mach/mach_init.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <sys/mman.h>
#include <unistd.h>

#include <AvailabilityMacros.h>

#include <errno.h>
#include <libkern/OSAtomic.h>
#include <mach/mach.h>
#include <mach/semaphore.h>
#include <mach/task.h>
#include <mach/vm_statistics.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>

#include "UnifiedInterface/platform-darwin/mach_vm.h"
#include "PlatformUtil/ProcessRuntimeUtility.h"

#include <vector>

// ================================================================
// GetProcessMemoryLayout

static bool memory_region_comparator(MemoryRegion a, MemoryRegion b) {
  return (a.address < b.address);
}

std::vector<MemoryRegion> ProcessMemoryLayout;
std::vector<MemoryRegion> ProcessRuntimeUtility::GetProcessMemoryLayout() {
  if (!ProcessMemoryLayout.empty()) {
    ProcessMemoryLayout.clear();
  }

  struct vm_region_submap_short_info_64 submap_info;
  mach_msg_type_number_t                count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
  mach_vm_address_t                     addr  = 0;
  mach_vm_size_t                        size  = 0;
  natural_t                             depth = 0;
  while (true) {
    count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    kern_return_t kr =
        mach_vm_region_recurse(mach_task_self(), &addr, &size, &depth, (vm_region_recurse_info_t)&submap_info, &count);
    if (kr != KERN_SUCCESS) {
      if (kr == KERN_INVALID_ADDRESS) {
        break;
      } else {
        break;
      }
    }

    if (submap_info.is_submap) {
      depth++;
    } else {
      MemoryPermission permission;
      if ((submap_info.protection & PROT_READ) && (submap_info.protection & PROT_WRITE)) {
        permission = MemoryPermission::kReadWrite;
      } else if ((submap_info.protection & PROT_READ) == submap_info.protection) {
        permission = MemoryPermission::kRead;
      } else if ((submap_info.protection & PROT_READ) && (submap_info.protection & PROT_EXEC)) {
        permission = MemoryPermission::kReadExecute;
      } else {
        continue;
      }
      MemoryRegion region = {(void *)addr, static_cast<size_t>(size), permission};
#if 0
      LOG("%p - %p", addr, addr + size);
#endif
      ProcessMemoryLayout.push_back(region);
    }

    addr += size;
  }

  std::sort(ProcessMemoryLayout.begin(), ProcessMemoryLayout.end(), memory_region_comparator);

  return ProcessMemoryLayout;
}

// ================================================================
// GetProcessModuleMap

std::vector<RuntimeModule> ProcessModuleMap;
std::vector<RuntimeModule> ProcessRuntimeUtility::GetProcessModuleMap() {
  if (!ProcessMemoryLayout.empty()) {
    ProcessMemoryLayout.clear();
  }
  int image_count = _dyld_image_count();
  for (size_t i = 0; i < image_count; i++) {
    const struct mach_header *header = NULL;
    header                           = _dyld_get_image_header(i);
    const char *path                 = NULL;
    path                             = _dyld_get_image_name(i);

    RuntimeModule module = {0};
    {
      strncpy(module.path, path, sizeof(module.path));
      module.load_address = (void *)header;
    }
    ProcessModuleMap.push_back(module);
  }
  return ProcessModuleMap;
}

RuntimeModule ProcessRuntimeUtility::GetProcessModule(const char *name) {
  std::vector<RuntimeModule> ProcessModuleMap = GetProcessModuleMap();
  for (auto module : ProcessModuleMap) {
    if (strstr(module.path, name) != 0) {
      return module;
    }
  }
  return RuntimeModule{0};
}
