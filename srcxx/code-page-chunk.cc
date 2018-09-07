#include "code-page-chunk.h"
#include "vm_core/platform/platform.h"
#include "vm_core/arch/cpu.h"

MemoryOperationError Patch(void *page_address, int offset, void *buffer, int size) {
  int page_size = OS::PageSize();

#ifdef __APPLE__
  void *remap_page = PageAllocator::Allocate(MemoryPermission::kReadWrite);

  vm_prot_t prot;
  vm_inherit_t inherit;
  kern_return_t kr;
  mach_port_t task_self = mach_task_self();
  vm_address_t region   = (vm_address_t)page_address;
  vm_size_t region_size = 0;
  struct vm_region_submap_short_info_64 info;
  mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
  natural_t max_depth               = 99999;
  kern_return_t kr;
  kr = vm_region_recurse_64(task_self, &region, &region_size, &max_depth, (vm_region_recurse_info_t)&info, &info_count);
  if (kr != KERN_SUCCESS) {
    return kMemoryOperationError;
  }

  kr = vm_copy(task_self, page_address, page_size, remap_page);
  if (kr != KERN_SUCCESS) {
    return kMemoryOperationError;
  }

  memcpy(remap_page + offset, buffer, size);

  OS::SetPermissions(remap_page, page_size, MemoryPermission::kReadExecute);

  mach_vm_address_t dest_page_address_ = (mach_vm_address_t)page_address;
  kr = mach_vm_remap(task_self, &dest_page_address_, page_size, 0, VM_FLAGS_OVERWRITE, task_self, TRUE, &cur_protection,
                     &max_protection, inherit);

  if (kr != KERN_SUCCESS) {
    return kMemoryOperationError;
  }

#elif __posix__
  OS::SetPermissions(page_address, page_size, MemoryPermission::kReadWriteExecute);
  memcpy(page_address + offset, buffer, size);
  OS::SetPermissions(page_address, page_size, MemoryPermission::kReadExecute);
#endif

  CPU::FlushCache();
  return kMemoryOperationSuccess;
}

MemoryOperationError Patch(void *address, void *buffer, int size) {
  int page_size          = OS::PageSize();
  int page_align_address = ALIGN_FLOOR(address, page_size);
  int offset             = address - page_align_address;

  return CodePageChunk::Patch(page_align_address, offset, buffer, size);
}

void *FinalizeAssembler(Assembler *assembler) {
  int code_size      = assembler->CodeSize();
  void *code_address = Allocate(code_size);
  assembler->Commit(code_address);
  CodeBuffer *code_buffer = assembler->GetBuffer();
  Patch(code_address, code_buffer->raw_byte(), code_size);
  Code *code = assembler->GetCode();
  return code->pointer();
}