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
      ERROR_LOG("mach error: %d", kr);                                                                                 \
      return failure;                                                                                                  \
    }                                                                                                                  \
  } while (0);

PUBLIC MemoryOperationError CodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
  if (address == nullptr || buffer == nullptr || buffer_size == 0) {
    FATAL("invalid argument");
    return kMemoryOperationError;
  }

  kern_return_t kr;

  {
    static pmap_paddr_t (*pmap_find_pa)(pmap_t pmap, addr64_t va) = nullptr;
    if (pmap_find_pa == nullptr) {
      void *func_ptr = nullptr;
      func_ptr = DobbySymbolResolver(nullptr, "_pmap_find_pa");
      if (func_ptr == nullptr)
        return kMemoryOperationError;
      func_ptr = ptrauth_strip((void *)func_ptr, ptrauth_key_asia);
      func_ptr = ptrauth_sign_unauthenticated(func_ptr, ptrauth_key_asia, 0);
      pmap_find_pa = (typeof(pmap_find_pa))func_ptr;
    }

    addr64_t dst = (addr64_t)pmap_find_pa(kernel_pmap, (addr64_t)address);
    addr64_t src = (addr64_t)pmap_find_pa(kernel_pmap, (addr64_t)buffer);

    static void (*bcopy_phys)(addr64_t from, addr64_t to, vm_size_t bytes) = nullptr;
    if (bcopy_phys == nullptr) {
      void *func_ptr = nullptr;
      func_ptr = DobbySymbolResolver(nullptr, "_bcopy_phys");
      if (func_ptr == nullptr)
        return kMemoryOperationError;
      func_ptr = ptrauth_strip((void *)func_ptr, ptrauth_key_asia);
      func_ptr = ptrauth_sign_unauthenticated(func_ptr, ptrauth_key_asia, 0);
      bcopy_phys = (typeof(bcopy_phys))func_ptr;
    }
    bcopy_phys(src, dst, buffer_size);

    // flush_dcache64(dst, (unsigned int)buffer_size, TRUE);
    // invalidate_icache64(dst, (unsigned int)buffer_size, TRUE);
  }
  if (0) {
    vm_map_t self_task = kernel_map;

    int page_size = PAGE_SIZE;
    addr_t page_aligned_address = ALIGN_FLOOR(address, page_size);
    int offset = (int)((addr_t)address - page_aligned_address);

    mach_vm_address_t remap_dummy_page = 0;
    kr = mach_vm_allocate(self_task, &remap_dummy_page, page_size, VM_FLAGS_ANYWHERE);
    KERN_RETURN_ERROR(kr, kMemoryOperationError);

    // copy original page
    memcpy((void *)remap_dummy_page, (void *)page_aligned_address, page_size);

    // patch buffer
    memcpy((void *)(remap_dummy_page + offset), buffer, buffer_size);

    // change permission
    kr = mach_vm_protect(self_task, remap_dummy_page, page_size, false, VM_PROT_READ | VM_PROT_EXECUTE);
    KERN_RETURN_ERROR(kr, kMemoryOperationError);

    static boolean_t (*vm_map_lookup_entry)(vm_map_t map, vm_map_offset_t address, vm_map_entry_t * entry) = nullptr;
    if (vm_map_lookup_entry == nullptr)
      vm_map_lookup_entry = (typeof(vm_map_lookup_entry))DobbySymbolResolver(nullptr, "_vm_map_lookup_entry");

    vm_map_entry_t entry;
    kr = vm_map_lookup_entry(kernel_map, (vm_map_offset_t)address, &entry);
    KERN_RETURN_ERROR(kr, kMemoryOperationError);

    struct vm_map_entry_flags {
      unsigned int dummy_bits : 17, permanent;
    };
    struct vm_map_entry_flags *flags = (typeof(flags))((addr_t)entry + 0x48);
    if (flags->permanent) {
      flags->permanent = 0;
    }

    mach_vm_address_t remap_dest_page = page_aligned_address;
    vm_prot_t curr_protection, max_protection;
    kr = mach_vm_remap(self_task, &remap_dest_page, page_size, 0, VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED, self_task,
                       remap_dummy_page, TRUE, &curr_protection, &max_protection, VM_INHERIT_COPY);
    KERN_RETURN_ERROR(kr, kMemoryOperationError);

    kr = mach_vm_deallocate(self_task, remap_dummy_page, page_size);
    KERN_RETURN_ERROR(kr, kMemoryOperationError);

    ClearCache(address, (void *)((addr_t)address + buffer_size));
    flush_dcache((vm_offset_t)address, (vm_size_t)buffer_size, 0);
    invalidate_icache((vm_offset_t)address, (vm_size_t)buffer_size, 0);
  }

  return kMemoryOperationSuccess;
}
