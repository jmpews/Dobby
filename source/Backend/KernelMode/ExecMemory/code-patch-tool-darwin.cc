#include "dobby_internal.h"

#include "PlatformUnifiedInterface/ExecMemory/ClearCacheTool.h"

#include <mach/mach_types.h>
#include <vm/vm_kern.h>
#include <mach/mach_vm.h>

#undef max
#undef min
#include <libkern/libkern.h>

#define KERN_RETURN_ERROR(kr, failure)                                                                                 \
  do {                                                                                                                 \
    if (kr != KERN_SUCCESS) {                                                                                          \
      ERROR_LOG("mach error: %s", mach_error_string(kr));                                                              \
      return failure;                                                                                                  \
    }                                                                                                                  \
  } while (0);

PUBLIC MemoryOperationError CodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
  if (address == nullptr || buffer == nullptr || buffer_size == 0) {
    FATAL("invalid argument");
    return kMemoryOperationError;
  }

  kern_return_t kr;

  int page_size = PAGE_SIZE;
  addr_t page_aligned_address = ALIGN_FLOOR(address, page_size);
  int offset = (int)((addr_t)address - page_aligned_address);

  vm_map_t self_task = kernel_map;

  mach_vm_address_t remap_dummy_page = 0;
  kr = mach_vm_allocate(self_task, &remap_dummy_page, page_size, VM_FLAGS_ANYWHERE);
  KERN_RETURN_ERROR(kr, kMemoryOperationError);

  // copy original page
  memcpy((void *)remap_dummy_page, (void *)page_aligned_address, page_size);

  // patch buffer
  memcpy((void *)(remap_dummy_page + offset), buffer, buffer_size);

  // change permission
  kr = mach_vm_protect(self_task, remap_dummy_page, page_size, false, VM_PROT_READ | VM_PROT_WRITE);
  KERN_RETURN_ERROR(kr, kMemoryOperationError);

  mach_vm_address_t remap_dest_page = page_aligned_address;
  vm_prot_t curr_protection, max_protection;
  kr = mach_vm_remap(self_task, &remap_dest_page, page_size, 0, VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED, self_task,
                     remap_dummy_page, TRUE, &curr_protection, &max_protection, VM_INHERIT_COPY);
  KERN_RETURN_ERROR(kr, kMemoryOperationError);

  kr = mach_vm_deallocate(self_task, remap_dummy_page, page_size);
  KERN_RETURN_ERROR(kr, kMemoryOperationError)

  ClearCache(address, (void *)((addr_t)address + buffer_size));
  flush_dcache((vm_offset_t)address, (vm_size_t)buffer_size, 0);
  invalidate_icache((vm_offset_t)address, (vm_size_t)buffer_size, 0);

  return kMemoryOperationSuccess;
}
