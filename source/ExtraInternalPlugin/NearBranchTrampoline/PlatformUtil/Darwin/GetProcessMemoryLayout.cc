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

#include "ExtraInternalPlugin/NearBranchTrampoline/PlatformUtil/GetProcessMemoryLayout.h"

#include "ExecMemory/ExecutableMemoryArena.h"

#include <vector>

std::vector<MemoryRegion> GetProcessMemoryLayout() {
  std::vector<MemoryRegion> result;

  mach_msg_type_number_t count;
  struct vm_region_submap_info_64 info;
  vm_size_t nesting_depth;
  kern_return_t kr = KERN_SUCCESS;

  vm_address_t addr = 0;
  vm_size_t size    = 0;

  while (1) {
    count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kr = vm_region_recurse_64(mach_task_self(), &addr, &size, (natural_t *)&nesting_depth, (vm_region_info_64_t)&info,
                              &count);
    if (kr == KERN_INVALID_ADDRESS) {
      break;
    } else if (kr) {
      mach_error("vm_region:", kr);
      break; /* last region done */
    }

    if (info.is_submap) {
      nesting_depth++;
    } else {
      addr += size;
      uintptr_t start = addr - size;
      uintptr_t end   = addr;
      MemoryPermission permission;
      if ((info.protection & PROT_READ) && (info.protection & PROT_WRITE)) {
        permission = MemoryPermission::kReadWrite;
      } else if ((info.protection & PROT_READ) == info.protection) {
        permission = MemoryPermission::kRead;
      } else if ((info.protection & PROT_READ) && (info.protection & PROT_EXEC)) {
        permission = MemoryPermission::kReadExecute;
      } else {
        continue;
      }
      MemoryRegion region = {start, end, permission};
      result.push_back(region);
    }
  }
  return result;
}