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

  int page_size = PAGE_SIZE;
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

  kern_return_t kr;
  vm_map_t self_task = mach_task_self();

  mach_vm_address_t remap_dummy_page = 0;
  kr = mach_vm_allocate(self_task, &remap_dummy_page, page_size, VM_FLAGS_ANYWHERE);
  KERN_RETURN_ERROR(kr, -1);

  // copy original page
  memcpy((void *)remap_dummy_page, (void *)patch_page, page_size);

  // patch buffer
  int offset = (int)((addr_t)address - patch_page);
  memcpy((void *)(remap_dummy_page + offset), buffer, buffer_size);

  mach_vm_address_t remap_dest_page = patch_page;

  //  int orig_prot = 0, orig_max_prot = 0;
  //  {
  //    vm_region_flavor_t flavor = VM_REGION_BASIC_INFO_64;
  //    vm_region_basic_info_data_64_t info;
  //    mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
  //    mach_port_t object_name;
  //    mach_vm_address_t address = remap_dest_page;
  //    mach_vm_size_t size = 0;
  //    kr = mach_vm_region(self_task, &address, &size, flavor, (vm_region_info_t)&info, &infoCnt, &object_name);
  //    KERN_RETURN_ERROR(kr, kMemoryOperationError);
  //
  //    orig_prot = info.protection;
  //    orig_max_prot = info.max_protection;
  //
  //    if(orig_prot == 1) {
  //      // change permission
  //      kr = mach_vm_protect(self_task, remap_dest_page, page_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
  //      KERN_RETURN_ERROR(kr, kMemoryOperationError);
  //
  //      address = remap_dest_page;
  //      kr = mach_vm_region(self_task, &address, &size, flavor, (vm_region_info_t)&info, &infoCnt, &object_name);
  //
  ////      kr = mach_vm_protect(self_task, remap_dest_page, page_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
  ////      KERN_RETURN_ERROR(kr, kMemoryOperationError);
  ////
  ////      address = remap_dest_page;
  ////      kr = mach_vm_region(self_task, &address, &size, flavor, (vm_region_info_t)&info, &infoCnt, &object_name);
  ////      KERN_RETURN_ERROR(kr, kMemoryOperationError);
  //      orig_prot = info.protection;
  //      orig_max_prot = info.max_protection;
  //    }
  //  }

  // change permission
  kr = mach_vm_protect(self_task, remap_dummy_page, page_size, false, VM_PROT_READ | VM_PROT_EXECUTE);
  KERN_RETURN_ERROR(kr, -1);

  vm_prot_t curr_protection, max_protection;
  kr = mach_vm_remap(self_task, &remap_dest_page, page_size, 0, VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED, self_task,
                     remap_dummy_page, true, &curr_protection, &max_protection, VM_INHERIT_COPY);
  if (kr == KERN_NO_SPACE) {
    mach_vm_protect(self_task, remap_dest_page, page_size, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    kr = mach_vm_remap(self_task, &remap_dest_page, page_size, 0, VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED, self_task,
                       remap_dummy_page, TRUE, &curr_protection, &max_protection, VM_INHERIT_COPY);
    mach_vm_protect(self_task, remap_dest_page, page_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
  }
  KERN_RETURN_ERROR(kr, -1);

  kr = mach_vm_deallocate(self_task, remap_dummy_page, page_size);
  KERN_RETURN_ERROR(kr, -1);

  ClearCache(address, (void *)((addr_t)address + buffer_size));

  return 0;
}
