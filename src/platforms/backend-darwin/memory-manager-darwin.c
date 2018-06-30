#include <errno.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>

#include "mach_vm.h"
#include "memory-helper-darwin.h"
#include "memory_manager.h"
#include "core.h"

PLATFORM_API bool memory_manager_cclass(is_support_allocate_rx_memory)(memory_manager_t *self) { return true; }

PLATFORM_API void memory_manager_cclass(get_process_memory_layout)(memory_manager_t *self) {

    mach_msg_type_number_t count;
    struct vm_region_submap_info_64 info;
    vm_size_t nesting_depth;

    kern_return_t kr      = KERN_SUCCESS;
    vm_address_t tmp_addr = 0;
    vm_size_t tmp_size    = 0;

    while (1) {
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr    = vm_region_recurse_64(mach_task_self(), &tmp_addr, &tmp_size, (natural_t *)&nesting_depth,
                                  (vm_region_info_64_t)&info, &count);
        if (kr == KERN_INVALID_ADDRESS) {
            break;
        } else if (kr) {
            mach_error("vm_region:", kr);
            break; /* last region done */
        }

        if (info.is_submap) {
            nesting_depth++;
        } else {
            MemoryBlock *mb = SAFE_MALLOC_TYPE(MemoryBlock);
            list_rpush(self->process_memory_layout, list_node_new(mb));
            tmp_addr += tmp_size;
            mb->address = (void *)((zz_addr_t)tmp_addr - tmp_size);
            mb->size    = tmp_size;
            mb->prot    = info.protection;
        }
    }
}

#if !USE_POSIX_IN_DARWIN
PLATFORM_API int memory_manager_cclass(get_page_size)() {
    int page_size = darwin_memory_helper_cclass(get_page_size)();
    return page_size;
}
#endif

#if !USE_POSIX_IN_DARWIN
PLATFORM_API void memory_manager_cclass(set_page_permission)(void *page_address, int prot, int n) {
    darwin_memory_helper_cclass(set_page_permission)(page_address, prot, n);
    return;
}
#endif

#if !USE_POSIX_IN_DARWIN
PLATFORM_API void *memory_manager_cclass(allocate_page)(memory_manager_t *self, int prot, int n) {
    vm_address_t page_address;
    kern_return_t kr;
    vm_size_t page_size;

    page_size = darwin_memory_helper_cclass(get_page_size)();
    /* use vm_allocate not mmap */
    kr = mach_vm_allocate(mach_task_self(), (mach_vm_address_t *)&page_address, page_size * n, VM_FLAGS_ANYWHERE);
    /* set page permission */
    darwin_memory_helper_cclass(set_page_permission)((void *)page_address, prot, n);

    return (void *)page_address;
}
#endif

#if !USE_POSIX_IN_DARWIN
/*
  REF:
  substitute/lib/darwin/execmem.c:execmem_foreign_write_with_pc_patch
  frida-gum-master/gum/gummemory.c:gum_memory_patch_code
  frida-gum-master/gum/backend-darwin/gummemory-darwin.c:gum_alloc_n_pages

  mach mmap use __vm_allocate and __vm_map
  https://github.com/bminor/glibc/blob/master/sysdeps/mach/hurd/mmap.c
  https://github.com/bminor/glibc/blob/master/sysdeps/mach/munmap.c

  http://shakthimaan.com/downloads/hurd/A.Programmers.Guide.to.the.Mach.System.Calls.pdf
*/
PLATFORM_API void memory_manager_cclass(patch_code)(memory_manager_t *self, void *dest, void *src, int count) {

    vm_address_t dest_page;
    vm_size_t offset;

    int page_size = memory_manager_cclass(get_page_size)();

    // https://www.gnu.org/software/hurd/gnumach-doc/Memory-Attributes.html
    dest_page = (zz_addr_t)dest & ~(page_size - 1);
    offset    = (zz_addr_t)dest - dest_page;

    vm_prot_t prot;
    vm_inherit_t inherit;
    kern_return_t kr;
    mach_port_t task_self = mach_task_self();

    darwin_memory_helper_cclass(get_memory_info)((void *)dest_page, &prot, &inherit);

    // For another method, pelease read `REF`;

    // zz_ptr_t code_mmap = mmap(NULL, range_size, PROT_READ | PROT_WRITE,
    //                           MAP_ANON | MAP_SHARED, -1, 0);
    // if (code_mmap == MAP_FAILED) {
    //   return;
    // }

    void *copy_page = memory_manager_cclass(allocate_page)(self, PROT_RW_, 1);

    kr = vm_copy(task_self, (vm_address_t)dest_page, page_size, (vm_address_t)copy_page);
    if (kr != KERN_SUCCESS) {
        ERROR_LOG_STR("[[memory_manager_cclass(patch_code)]]");
        return;
    }
    memcpy((void *)((zz_addr_t)copy_page + offset), src, count);

    // SAME: mprotect(code_mmap, range_size, prot);
    darwin_memory_helper_cclass(set_page_permission)(copy_page, PROT_R_X, 1);

    // TODO: need check `memory region` again.

    // // if only with this, `memory region` is `r-x`
    // vm_protect((vm_map_t)mach_task_self(), 0x00000001816b2030, 16, FALSE, 0x13);
    // // and with this, `memory region` is `rwx`
    // *(char *)0x00000001816b01a8 = 'a';

    mach_vm_address_t target_address = (vm_address_t)dest_page;
    vm_prot_t cur_protection, max_protection;
    kr = mach_vm_remap(task_self, &target_address, page_size, 0, VM_FLAGS_OVERWRITE, task_self,
                       (mach_vm_address_t)copy_page,
                       /*copy*/ TRUE, &cur_protection, &max_protection, inherit);

    if (kr != KERN_SUCCESS) {
        ERROR_LOG_STR("[[memory_manager_cclass(patch_code)]]");
        // LOG-NEED
    }
    // read `REF`
    // munmap(code_mmap, range_size);
    kr = mach_vm_deallocate(task_self, (mach_vm_address_t)copy_page, page_size);
    if (kr != KERN_SUCCESS) {
        ERROR_LOG_STR("[[memory_manager_cclass(patch_code)]]");
    }
}
#endif
