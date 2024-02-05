#include "dobby/dobby_internal.h"

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <mach/mach_init.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/dyld_images.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>

#include <unistd.h>

#include <AvailabilityMacros.h>

#include <libkern/OSAtomic.h>
#include <mach/mach.h>
#include <mach/semaphore.h>
#include <mach/task.h>
#include <mach/vm_statistics.h>

#include "UnifiedInterface/platform-darwin/mach_vm.h"
#include "PlatformUtil/ProcessRuntime.h"

static bool memory_region_comparator(MemRegion a, MemRegion b) {
  return (a.addr() < b.addr());
}

stl::vector<MemRegion> *regions;

const stl::vector<MemRegion> &ProcessRuntime::getMemoryLayout() {
  if (regions == nullptr) {
    regions = new stl::vector<MemRegion>();
  }

  regions->clear();

  vm_region_submap_info_64 region_submap_info;
  mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
  mach_vm_address_t addr = 0;
  mach_vm_size_t size = 0;
  natural_t depth = 0;
  while (true) {
    count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr = mach_vm_region_recurse(mach_task_self(), (mach_vm_address_t *)&addr, (mach_vm_size_t *)&size,
                                              &depth, (vm_region_recurse_info_t)&region_submap_info, &count);
    if (kr != KERN_SUCCESS) {
      if (kr == KERN_INVALID_ADDRESS) {
        break;
      } else {
        break;
      }
    }

    if (region_submap_info.is_submap) {
      depth++;
    } else {
      MemoryPermission perm = kNoAccess;
      auto prot = region_submap_info.protection;
      if (prot & VM_PROT_READ) {
        perm = (MemoryPermission)(perm | kRead);
      }
      if (prot & VM_PROT_WRITE) {
        perm = (MemoryPermission)(perm | kWrite);
      }
      if (prot & VM_PROT_EXECUTE) {
        perm = (MemoryPermission)(perm | kExecute);
      }
      // INFO_LOG("%p --- %p --- %p --- %d", addr, addr + size, size, region_submap_info.protection);

      MemRegion region = MemRegion(addr, size, perm);
      regions->push_back(region);
      addr += size;
    }
  }

  // std::sort(ProcessMemoryLayout.begin(), ProcessMemoryLayout.end(), memory_region_comparator);

  return *regions;
}

static stl::vector<RuntimeModule> *modules;

const stl::vector<RuntimeModule> &ProcessRuntime::getModuleMap() {
  if (modules == nullptr) {
    modules = new stl::vector<RuntimeModule>();
  }
  modules->clear();

  kern_return_t kr;
  task_dyld_info_data_t task_dyld_info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  kr = task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);
  if (kr != KERN_SUCCESS) {
    return *modules;
  }

  struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)task_dyld_info.all_image_info_addr;
  const struct dyld_image_info *infoArray = infos->infoArray;
  uint32_t infoArrayCount = infos->infoArrayCount;

  RuntimeModule module = {0};
  strncpy(module.path, "dummy-placeholder-module", sizeof(module.path) - 1);
  module.base = 0;
  modules->push_back(module);

  strncpy(module.path, infos->dyldPath, sizeof(module.path) - 1);
  module.base = (void *)infos->dyldImageLoadAddress;
  modules->push_back(module);

  for (int i = 0; i < infoArrayCount; ++i) {
    const struct dyld_image_info *info = &infoArray[i];

    {
      strncpy(module.path, info->imageFilePath, sizeof(module.path) - 1);
      module.base = (void *)info->imageLoadAddress;
      modules->push_back(module);
    }
  }

  modules->sort([](const RuntimeModule &a, const RuntimeModule &b) -> int { return a.base < b.base; });

  return *modules;
}

RuntimeModule ProcessRuntime::getModule(const char *name) {
  auto modules = getModuleMap();
  for (auto module : modules) {
    if (strstr(module.path, name) != 0) {
      return module;
    }
  }
  return RuntimeModule{0};
}
