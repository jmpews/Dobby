#include <core/arch/Cpu.h>

#include "PlatformInterface/Common/Platform.h"
#include "PlatformInterface/ExecMemory/ClearCacheTool.h"

#include <unistd.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include "PlatformInterface/Common/platform-darwin/mach_vm.h"
#endif

#if defined(__APPLE__)
#include <dlfcn.h>
#include <mach/vm_statistics.h>
#endif

#include "logging/check_logging.h"

using namespace zz;

_MemoryOperationError CodePatch(void *address, void *buffer, int size) {

  int page_size             = (int)sysconf(_SC_PAGESIZE);
  addr_t page_align_address = ALIGN_FLOOR(address, page_size);
  int offset                = static_cast<int>((addr_t)address - page_align_address);

#ifdef __APPLE__

  addr_t remap_page =
      (addr_t)mmap(0, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, VM_MAKE_TAG(255), 0);
  if ((void *)remap_page == MAP_FAILED)
    return kMemoryOperationError;

  vm_prot_t prot;
  vm_inherit_t inherit;
  kern_return_t kr;
  mach_port_t task_self = mach_task_self();

  vm_address_t region   = (vm_address_t)page_align_address;
  vm_size_t region_size = 0;
  struct vm_region_submap_short_info_64 info;
  mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
  natural_t max_depth               = 99999;
  kr = vm_region_recurse_64(task_self, &region, &region_size, &max_depth, (vm_region_recurse_info_t)&info, &info_count);
  if (kr != KERN_SUCCESS) {
    return kMemoryOperationError;
  }
  prot    = info.protection;
  inherit = info.inheritance;

  kr = vm_copy(task_self, (vm_address_t)page_align_address, page_size, (vm_address_t)remap_page);
  CHECK_EQ(kr, KERN_SUCCESS);

  memcpy((void *)(remap_page + offset), buffer, size);

  mprotect((void *)remap_page, page_size, PROT_READ | PROT_EXEC);

  mach_vm_address_t dest_page_address_ = (mach_vm_address_t)page_align_address;
  vm_prot_t curr_protection, max_protection;
  kr = mach_vm_remap(task_self, &dest_page_address_, page_size, 0, VM_FLAGS_OVERWRITE, task_self,
                     (mach_vm_address_t)remap_page, TRUE, &curr_protection, &max_protection, inherit);

  if (kr != KERN_SUCCESS) {
    // perror((const char *)strerror(errno));
    return kMemoryOperationError;
  }

#endif

  addr_t clear_start_ = (addr_t)page_align_address + offset;
  ClearCache((void *)clear_start_, (void *)(clear_start_ + size));
  return kMemoryOperationSuccess;
}
