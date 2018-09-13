#include "vm_core_extra/code-page-chunk.h"
#include "vm_core/platform/platform.h"
#include "vm_core/base/page-allocator.h"
#include "vm_core/arch/cpu.h"

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include "vm_core/platform/platform-darwin/mach_vm.h"
#endif

using namespace zz;

std::vector<CodeChunk *> CodeChunk::code_pages_;

CodeChunk *CodeChunk::AllocateCodePage() {
  void *new_code_page   = PageAllocator::Allocate(OS::MemoryPermission::kReadExecute);
  CodeChunk *code_chunk = new CodeChunk(new_code_page, PageAllocator::PageSize());
  CodeChunk::code_pages_.push_back(code_chunk);
  return code_chunk;
}

MemoryRegion *CodeChunk::AllocateCode(size_t size) {
  MemoryRegion *region = nullptr;
  auto it              = CodeChunk::code_pages_.begin();
  for (it; it != CodeChunk::code_pages_.end(); it++) {
    region = (*it)->Allocate(size);
  }
  // Not found the free memory
  if (!region) {
    MemoryChunk *new_page = CodeChunk::AllocateCodePage();
    region                = new_page->Allocate(size);
    assert(region);
  }
  return region;
}

CodeChunk::_MemoryOperationError CodeChunk::Patch(void *page_address, int offset, void *buffer, int size) {
  int page_size = (int)PageAllocator::PageSize();

#ifdef __APPLE__
  // MemoryRegion *region = PageAllocator::Allocate(OS::MemoryPermission::kReadWrite);
  // uintptr_t remap_page = (uintptr_t)region->pointer();

  uintptr_t remap_page = (uintptr_t)PageAllocator::Allocate(OS::MemoryPermission::kReadWrite);

  vm_prot_t prot;
  vm_inherit_t inherit;
  kern_return_t kr;
  mach_port_t task_self = mach_task_self();
  
  // =====
  
  vm_address_t region   = (vm_address_t)page_address;
  vm_size_t region_size = 0;
  struct vm_region_submap_short_info_64 info;
  mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
  natural_t max_depth               = 99999;
  kr = vm_region_recurse_64(task_self, &region, &region_size, &max_depth, (vm_region_recurse_info_t)&info, &info_count);
  if (kr != KERN_SUCCESS) {
    return kMemoryOperationError;
  }
  prot = info.protection;
  inherit = info.inheritance;
  
  // =====
  
  kr = vm_copy(task_self, (vm_address_t)page_address, page_size, (vm_address_t)remap_page);
  if (kr != KERN_SUCCESS) {
    return kMemoryOperationError;
  }

  memcpy((void *)(remap_page + offset), buffer, size);
  
  // =====

  PageAllocator::SetPermissions((void *)remap_page, page_size, OS::MemoryPermission::kReadExecute);

  // =====
  
  mach_vm_address_t dest_page_address_ = (mach_vm_address_t)page_address;
  vm_prot_t cur_protection, max_protection;
  kr = mach_vm_remap(task_self, &dest_page_address_, page_size, 0, VM_FLAGS_OVERWRITE, task_self,
                     (mach_vm_address_t)remap_page, TRUE, &cur_protection, &max_protection, inherit);

  CHECK_EQ(kr, KERN_SUCCESS);
  if (kr != KERN_SUCCESS) {
    // perror((const char *)strerror(errno));
    return kMemoryOperationError;
  }

#elif __posix__
  OS::SetPermissions(page_address, page_size, MemoryPermission::kReadWriteExecute);
  memcpy(page_address + offset, buffer, size);
  OS::SetPermissions(page_address, page_size, MemoryPermission::kReadExecute);
#endif

  CPU::FlushCache((uintptr_t)page_address + offset, size);
  return kMemoryOperationSuccess;
}

CodeChunk::MemoryOperationError CodeChunk::Patch(void *address, void *buffer, int size) {
  size_t page_size             = PageAllocator::PageSize();
  uintptr_t page_align_address = ALIGN_FLOOR(address, page_size);
  int offset                   = (uintptr_t)address - page_align_address;

  return CodeChunk::Patch((void *)page_align_address, offset, buffer, size);
}

CodeChunk::MemoryOperationError CodeChunk::PatchCodeBuffer(void *address, CodeBuffer *buffer) {
  void *code_buffer = buffer->RawBuffer();
  int code_size     = buffer->Size();
  CodeChunk::Patch(address, code_buffer, code_size);
  return kMemoryOperationSuccess;
}
