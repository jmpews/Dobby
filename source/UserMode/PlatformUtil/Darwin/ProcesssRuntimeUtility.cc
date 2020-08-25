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

#include "UserMode/UnifiedInterface/platform-darwin/mach_vm.h"
#include "UserMode/PlatformUtil/ProcessRuntimeUtility.h"

#include <vector>

// ================================================================
// GetProcessMemoryLayout

static bool memory_region_comparator(MemoryRegion a, MemoryRegion b) {
  return (a.address > b.address);
}

std::vector<MemoryRegion> ProcessMemoryLayout;
std::vector<MemoryRegion> ProcessRuntimeUtility::GetProcessMemoryLayout() {
  if (!ProcessMemoryLayout.empty()) {
    ProcessMemoryLayout.clear();
  }

  struct vm_region_submap_short_info_64 submap_info;
  mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
  mach_vm_address_t addr       = 0;
  mach_vm_size_t size          = 0;
  natural_t depth              = 0;
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

    if (0 && submap_info.is_submap) {
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
      // LOG("%p - %p", addr, addr + size);
      ProcessMemoryLayout.push_back(region);
    }

    addr += size;
  }

  std::sort(ProcessMemoryLayout.begin(), ProcessMemoryLayout.end(), memory_region_comparator);

  return ProcessMemoryLayout;
}
