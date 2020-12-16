#include "dobby_internal.h"
#include "core/arch/Cpu.h"
#include "PlatformUnifiedInterface/ExecMemory/ClearCacheTool.h"
#include "UnifiedInterface/platform.h"

#include <unistd.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include "UserMode/UnifiedInterface/platform-darwin/mach_vm.h"
#endif

#if defined(__APPLE__)
#include <dlfcn.h>
#include <mach/vm_statistics.h>
#endif

#include "logging/check_logging.h"

#include "common/macros/platform_macro.h"
#if defined(CODE_PATCH_WITH_SUBSTRATED) && defined(TARGET_ARCH_ARM64)
#include <mach/mach.h>
#include "bootstrap.h"
#include "ExecMemory/substrated/mach_interface_support/substrated_client.h"

#define KERN_ERROR_RETURN(err, failure)                                                                                \
  do {                                                                                                                 \
    if (err != KERN_SUCCESS) {                                                                                         \
      return failure;                                                                                                  \
    }                                                                                                                  \
  } while (0);

static mach_port_t substrated_server_port = MACH_PORT_NULL;

mach_port_t connect_mach_service(const char *name) {
  mach_port_t   port = MACH_PORT_NULL;
  kern_return_t kr;

  kr = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap_port);
  KERN_ERROR_RETURN(kr, MACH_PORT_NULL)

  kr = bootstrap_look_up(bootstrap_port, (char *)name, &port);
  KERN_ERROR_RETURN(kr, MACH_PORT_NULL);

  substrated_server_port = port;

  return port;
}

int code_remap_with_substrated(uint8_t *buffer, uint32_t buffer_size, addr_t address) {
  if (!MACH_PORT_VALID(substrated_server_port)) {
    substrated_server_port = connect_mach_service("cy:com.saurik.substrated");
  }
  if (!MACH_PORT_VALID(substrated_server_port))
    return -1;

  kern_return_t kr;
  kr = substrated_mark(substrated_server_port, mach_task_self(), (mach_vm_address_t)buffer, buffer_size,
                       (mach_vm_address_t *)&address);
  if (kr != KERN_SUCCESS) {
    return RT_FAILED;
  }
  return RT_SUCCESS;
}
#endif

PUBLIC MemoryOperationError CodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
  kern_return_t kr;

  int    page_size          = (int)sysconf(_SC_PAGESIZE);
  addr_t page_align_address = ALIGN_FLOOR(address, page_size);
  int    offset             = static_cast<int>((addr_t)address - page_align_address);

  static mach_port_t self_port = mach_task_self();
#ifdef __APPLE__

#if 0 // REMOVE
  vm_prot_t prot;
  vm_inherit_t inherit;
  mach_port_t task_self = mach_task_self();
  vm_address_t region   = (vm_address_t)page_align_address;
  vm_size_t region_size = 0;
  struct vm_region_submap_short_info_64 info;
  mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
  natural_t max_depth               = -1;
  kr = vm_region_recurse_64(task_self, &region, &region_size, &max_depth, (vm_region_recurse_info_t)&info, &info_count);
  if (kr != KERN_SUCCESS) {
    return kMemoryOperationError;
  }
  prot    = info.protection;
  inherit = info.inheritance;
#endif

  // try modify with substrated (steal from frida-gum)

  addr_t remap_page =
      (addr_t)mmap(0, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, VM_MAKE_TAG(255), 0);
  if ((void *)remap_page == MAP_FAILED)
    return kMemoryOperationError;

  // copy origin page
  memcpy((void *)remap_page, (void *)page_align_address, page_size);

  // patch buffer
  memcpy((void *)(remap_page + offset), buffer, buffer_size);

  // change permission
  mprotect((void *)remap_page, page_size, PROT_READ | PROT_WRITE);

  int ret = RT_FAILED;
#if defined(CODE_PATCH_WITH_SUBSTRATED) && defined(TARGET_ARCH_ARM64)
  ret = code_remap_with_substrated((uint8_t *)remap_page, (uint32_t)page_size, (addr_t)page_align_address);
  if (0 && ret == RT_FAILED)
    DLOG(0, "substrated failed, use vm_remap");
#endif
  if (ret == RT_FAILED) {
    mprotect((void *)remap_page, page_size, PROT_READ | PROT_EXEC);
    mach_vm_address_t dest_page_address_ = (mach_vm_address_t)page_align_address;
    vm_prot_t         curr_protection, max_protection;
    kr = mach_vm_remap(self_port, &dest_page_address_, page_size, 0, VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED, self_port,
                       (mach_vm_address_t)remap_page, TRUE, &curr_protection, &max_protection, VM_INHERIT_COPY);
    if (kr != KERN_SUCCESS) {
      return kMemoryOperationError;
    }
  }

  // unmap the origin page
  int err = munmap((void *)remap_page, (mach_vm_address_t)page_size);
  if (err == -1) {
    return kMemoryOperationError;
  }

#endif

  addr_t clear_start = (addr_t)page_align_address + offset;
  DCHECK_EQ(clear_start, (addr_t)address);

  ClearCache((void *)address, (void *)((addr_t)address + buffer_size));
  return kMemoryOperationSuccess;
}
