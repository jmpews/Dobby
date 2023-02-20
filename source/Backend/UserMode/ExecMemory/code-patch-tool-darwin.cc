#include "dobby/dobby_internal.h"

#include "PlatformUnifiedInterface/ExecMemory/ClearCacheTool.h"

#include <unistd.h>

#include <mach/mach.h>
#include "UnifiedInterface/platform-darwin/mach_vm.h"

#if defined(__APPLE__)
#include <dlfcn.h>
#include <mach/vm_statistics.h>
#endif

#define KERN_RETURN_ERROR(kr, failure)                                                                                 \
  do {                                                                                                                 \
    if (kr != KERN_SUCCESS) {                                                                                          \
      ERROR_LOG("mach error: %s", mach_error_string(kr));                                                              \
      return failure;                                                                                                  \
    }                                                                                                                  \
  } while (0);

PUBLIC int DobbyCodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
  if (address == nullptr || buffer == nullptr || buffer_size == 0) {
    ERROR_LOG("invalid argument");
    return -1;
  }

  size_t page_size = PAGE_SIZE;
  addr_t patch_page = ALIGN_FLOOR(address, page_size);

  // cross over page
  if ((addr_t)address + buffer_size > patch_page + page_size) {
    void *address_a = address;
    uint8_t *buffer_a = buffer;
    uint32_t buffer_size_a = (patch_page + page_size - (addr_t)address);
    auto ret = DobbyCodePatch(address_a, buffer_a, buffer_size_a);
    if (ret == -1) {
      return ret;
    }

    void *address_b = (void *)((addr_t)address + buffer_size_a);
    uint8_t *buffer_b = buffer + buffer_size_a;
    uint32_t buffer_size_b = buffer_size - buffer_size_a;
    ret = DobbyCodePatch(address_b, buffer_b, buffer_size_b);
    return ret;
  }

  addr_t remap_dest_page = patch_page;
  mach_vm_address_t remap_dummy_page = 0;

  auto self_task = mach_task_self();
  kern_return_t kr;

  static int is_enable_remap = -1;
  if (is_enable_remap == -1) {
    auto kr = mach_vm_protect(self_task, remap_dest_page, page_size, false, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr == KERN_SUCCESS) {
      is_enable_remap = 1;
    } else {
      is_enable_remap = 0;
    }
  }
  if (is_enable_remap == 1) {
    addr_t remap_dummy_page = 0;
    {
      kr = mach_vm_allocate(self_task, (mach_vm_address_t *)&remap_dummy_page, page_size, VM_FLAGS_ANYWHERE);
      KERN_RETURN_ERROR(kr, -1);

      memcpy((void *)remap_dummy_page, (void *)patch_page, page_size);

      int offset = (int)((addr_t)address - patch_page);
      memcpy((void *)(remap_dummy_page + offset), buffer, buffer_size);

      kr = mach_vm_protect(self_task, remap_dummy_page, page_size, false, VM_PROT_READ | VM_PROT_EXECUTE);
      KERN_RETURN_ERROR(kr, -1);
    }

    vm_prot_t prot, max_prot;
    kr = mach_vm_remap(self_task, (mach_vm_address_t *)&remap_dest_page, page_size, 0,
                       VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED, self_task, remap_dummy_page, true, &prot, &max_prot,
                       VM_INHERIT_COPY);
    KERN_RETURN_ERROR(kr, -1);

    kr = mach_vm_deallocate(self_task, remap_dummy_page, page_size);
    KERN_RETURN_ERROR(kr, -1);
  } else {
    {
      auto kr = mach_vm_allocate(self_task, &remap_dummy_page, page_size, VM_FLAGS_ANYWHERE);
      KERN_RETURN_ERROR(kr, -1);

      kr = mach_vm_deallocate(self_task, remap_dummy_page, page_size);
      KERN_RETURN_ERROR(kr, -1);
    }

    vm_prot_t prot, max_prot;
    kr = mach_vm_remap(self_task, &remap_dummy_page, page_size, 0, VM_FLAGS_ANYWHERE, self_task, remap_dest_page, false,
                       &prot, &max_prot, VM_INHERIT_SHARE);
    KERN_RETURN_ERROR(kr, -1);

    kr = mach_vm_protect(self_task, remap_dummy_page, page_size, false, VM_PROT_READ | VM_PROT_WRITE);

    // the kr always return KERN_PROTECTION_FAILURE
    kr = KERN_PROTECTION_FAILURE;
    if (kr == KERN_PROTECTION_FAILURE) {
      kr = mach_vm_protect(self_task, remap_dest_page, page_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
      KERN_RETURN_ERROR(kr, -1);

      memcpy((void *)(patch_page + ((uint64_t)address - remap_dest_page)), buffer, buffer_size);

      kr = mach_vm_protect(self_task, remap_dest_page, page_size, false, VM_PROT_READ | VM_PROT_EXECUTE);
      KERN_RETURN_ERROR(kr, -1);
    } else {
      memcpy((void *)(remap_dummy_page + ((uint64_t)address - remap_dest_page)), buffer, buffer_size);
    }
  }

  ClearCache(address, (void *)((addr_t)address + buffer_size));

  return 0;
}
