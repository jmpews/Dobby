#include "memory-helper-darwin.h"

#include <unistd.h>

int darwin_memory_helper_cclass(get_page_size)() {
  return getpagesize();
}

void darwin_memory_helper_cclass(get_memory_info)(void *address, vm_prot_t *prot, vm_inherit_t *inherit) {
  vm_address_t region   = (vm_address_t)address;
  vm_size_t region_size = 0;
  struct vm_region_submap_short_info_64 info;
  mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
  natural_t max_depth               = 99999;
  kern_return_t kr;
  kr = vm_region_recurse_64(mach_task_self(), &region, &region_size, &max_depth, (vm_region_recurse_info_t)&info,
                            &info_count);
  if (kr != KERN_SUCCESS) {
    return;
  }
  *prot    = info.protection;
  *inherit = info.inheritance;
}

void darwin_memory_helper_cclass(set_page_memory_permission)(void *address, int prot) {
  kern_return_t kr;

  int page_size = memory_manager_cclass(get_page_size)();

  kr = mach_vm_protect(mach_task_self(), (vm_address_t)address, page_size, FALSE, prot);
  if (kr != KERN_SUCCESS) {
    // LOG-NEED
  }
}