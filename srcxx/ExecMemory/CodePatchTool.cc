#include <core/arch/Cpu.h>

#include "ExecMemory/CodePatchTool.h"
#include "PlatformInterface/platform.h"
#include "ExecMemory/PageAllocator.h"

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include "PlatformInterface/platform-darwin/mach_vm.h"
#endif

using namespace zz;

_MemoryOperationError CodePatchTool::Patch(void *page_address, int offset, void *buffer, int size) {
  int page_size = (int)OSMemory::PageSize();

#ifdef __APPLE__

  uintptr_t remap_page = (uintptr_t)PageAllocator::Allocate(MemoryPermission::kReadWrite);

  vm_prot_t prot;
  vm_inherit_t inherit;
  kern_return_t kr;
  mach_port_t task_self = mach_task_self();

  vm_address_t region   = (vm_address_t)page_address;
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

  kr = vm_copy(task_self, (vm_address_t)page_address, page_size, (vm_address_t)remap_page);
  if (kr != KERN_SUCCESS) {
    return kMemoryOperationError;
  }

  memcpy((void *)(remap_page + offset), buffer, size);

  PageAllocator::SetPermissions((void *)remap_page, MemoryPermission::kReadExecute);

  mach_vm_address_t dest_page_address_ = (mach_vm_address_t)page_address;
  vm_prot_t cur_protection, max_protection;
  kr = mach_vm_remap(task_self, &dest_page_address_, page_size, 0, VM_FLAGS_OVERWRITE, task_self,
                     (mach_vm_address_t)remap_page, TRUE, &cur_protection, &max_protection, inherit);

  if (kr != KERN_SUCCESS) {
    // perror((const char *)strerror(errno));
    return kMemoryOperationError;
  }

#elif defined(__ANDROID__) || defined(__linux__)
  PageAllocator::SetPermissions(page_address, page_size, MemoryPermission::kReadWriteExecute);
  memcpy((void *)((uintptr_t)page_address + offset), buffer, size);
  PageAllocator::SetPermissions(page_address, page_size, MemoryPermission::kReadExecute);
#endif

  CpuFeatures::FlushICache((void *)((uintptr_t)page_address + offset), size);
  return kMemoryOperationSuccess;
}

MemoryOperationError CodePatchTool::Patch(void *address, void *buffer, int size) {
  size_t page_size             = OSMemory::PageSize();
  uintptr_t page_align_address = ALIGN_FLOOR(address, page_size);
  int offset                   = (uintptr_t)address - page_align_address;

  return CodePatchTool::Patch((void *)page_align_address, offset, buffer, size);
}

MemoryOperationError CodePatchTool::PatchCodeBuffer(void *address, CodeBufferBase *buffer) {
  void *buffer_address = buffer->getRawBuffer();
  int buffer_size      = (int)buffer->getSize();
  CodePatchTool::Patch(address, buffer_address, buffer_size);
  return kMemoryOperationSuccess;
}
