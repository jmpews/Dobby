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

#include <cmath>

#include "platform.h"

void platform_darwin_test() { int dummy; }

namespace zz {
std::vector<OSMemory::SharedLibraryAddress> OSMemory::GetSharedLibraryAddresses() {
  std::vector<SharedLibraryAddress> result;
  unsigned int images_count = _dyld_image_count();
  for (unsigned int i = 0; i < images_count; ++i) {
    const mach_header *header = _dyld_get_image_header(i);
    if (header == nullptr)
      continue;
#if HOST_ARCH_X64
    uint64_t size;
    char *code_ptr =
        getsectdatafromheader_64(reinterpret_cast<const mach_header_64 *>(header), SEG_TEXT, SECT_TEXT, &size);
#else
    unsigned int size;
    char *code_ptr = getsectdatafromheader(header, SEG_TEXT, SECT_TEXT, &size);
#endif
    if (code_ptr == nullptr)
      continue;
    const intptr_t slide  = _dyld_get_image_vmaddr_slide(i);
    const uintptr_t start = reinterpret_cast<uintptr_t>(code_ptr) + slide;
    result.push_back(SharedLibraryAddress(_dyld_get_image_name(i), start, start + size, slide));
  }
  return result;
}

std::vector<OSMemory::MemoryRegion> OSMemory::GetMemoryLayout() {
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
      uintptr_t start = addr - size;
      uintptr_t end   = addr;
      MemoryPermission permission;
      if ((info.protection & PROT_READ) && (info.protection & PROT_WRITE)) {
        permission = OSMemory::MemoryPermission::kReadWrite;
      } else if ((info.protection & PROT_READ) == info.protection) {
        permission = OSMemory::MemoryPermission::kRead;
      } else if ((info.protection & PROT_READ) && (info.protection & PROT_EXEC)) {
        permission = OSMemory::MemoryPermission::kReadExecute;
      } else {
        continue;
      }
      result.push_back(OSMemory::MemoryRegion(start, end, permission));
    }
  }
  return result;
}

} // namespace zz
