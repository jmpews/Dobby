/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <mach/error.h>
#include <mach/vm_map.h>
#include <sys/mman.h>

#include <mach/mach.h>

#include "../../zzdeps/darwin/mach_vm.h"
#include "memory-darwin.h"
#include "../../zzdeps/darwin/memory-utils.h"

static kern_return_t get_page_info(uintptr_t ptr, vm_prot_t *prot_p,
                                   vm_inherit_t *inherit_p) {

    vm_address_t region = (vm_address_t) ptr;
    vm_size_t region_len = 0;
    struct vm_region_submap_short_info_64 info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t max_depth = 99999;
    kern_return_t kr =
            vm_region_recurse_64(mach_task_self(), &region, &region_len, &max_depth,
                                 (vm_region_recurse_info_t) &info, &info_count);
    *prot_p = info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC);
    *inherit_p = info.inheritance;
    return kr;
}


ZZSTATUS zz_mprotect(zpointer addr, zsize size, vm_prot_t page_prot) {
    kern_return_t kr;

    zsize page_size;
    zpointer aligned_address;
    zsize aligned_size;

    page_size = zz_query_page_size();
    aligned_address = (zpointer) ((zaddr) addr & ~(page_size - 1));
    aligned_size =
            (1 + ((addr + size - 1 - aligned_address) / page_size)) * page_size;

    kr = mach_vm_protect(mach_task_self(), (vm_address_t) aligned_address,
                         aligned_size, false, page_prot);
    if (kr != KERN_SUCCESS) {
        Serror("zz_mprotect error!");
        return ZZ_UNKOWN;
    }
    return ZZ_DONE;
}

/*
  TODO:
  bad code !!!
  should alloc from `page manager center`, and now will waste so much memory.
*/
zpointer zz_alloc_pages(zsize n_pages) {
    mach_vm_address_t result;
    kern_return_t kr;
    zsize page_size;
    page_size = zz_query_page_size();

    if (n_pages <= 0) {
        n_pages = 1;
    }

    kr = mach_vm_allocate(mach_task_self(), &result, page_size * n_pages,
                          VM_FLAGS_ANYWHERE);

    if (kr != KERN_SUCCESS) {
        Serror("zz_alloc_pages error!");
        return NULL;
    }

    zz_mprotect((zpointer) result, page_size * n_pages, (VM_PROT_DEFAULT | VM_PROT_COPY));

    return (zpointer) result;
}

zpointer zz_alloc_memory(zsize size) {
    zsize page_size;
    zuint n;

    page_size = zz_query_page_size();
    n = ((size + page_size - 1) & ~(page_size - 1)) / page_size;

    zpointer page_ptr = zz_alloc_pages(n);
    return page_ptr;
}

void make_page_executable(zpointer addr, zuint size) {
    // err = mprotect(aligned_address, aligned_size, PROT_EXEC | PROT_READ);
    // if (err) {
    //   Xerror("err = %x", err);
    // }
    zz_mprotect(addr, size, (VM_PROT_READ | VM_PROT_EXECUTE));
}

void make_page_writable(zpointer addr, zuint size) {
    ZZSTATUS zstatus;
    zstatus = zz_mprotect(addr, size, (VM_PROT_ALL | VM_PROT_COPY));
    if (zstatus == ZZ_UNKOWN) {
        zstatus = zz_mprotect(addr, size, (VM_PROT_DEFAULT | VM_PROT_COPY));
    }
    if (zstatus == ZZ_UNKOWN) {
        Serror("zz_alloc_pages error!");
    }
}


/*
  ref:
  substitute/lib/darwin/execmem.c:execmem_foreign_write_with_pc_patch
  frida-gum-master/gum/gummemory.c:gum_memory_patch_code

  frida-gum-master/gum/backend-darwin/gummemory-darwin.c:gum_alloc_n_pages

  mach mmap use __vm_allocate and __vm_map
  https://github.com/bminor/glibc/blob/master/sysdeps/mach/hurd/mmap.c
  https://github.com/bminor/glibc/blob/master/sysdeps/mach/munmap.c

  http://shakthimaan.com/downloads/hurd/A.Programmers.Guide.to.the.Mach.System.Calls.pdf
*/
void memory_patch_code(zpointer addr, zpointer code_ptr, zuint code_size) {
    zsize page_size;
    zpointer *start_page, *end_page;
    zsize page_offset, range_size;

    page_size = zz_query_page_size();
    /*
      https://www.gnu.org/software/hurd/gnumach-doc/Memory-Attributes.html
     */
    start_page = (zpointer) (((zsize) addr) & ~(page_size - 1));
    end_page = (zpointer) (((zsize) (addr + code_size - 1)) & ~(page_size - 1));
    page_offset = (zaddr) addr - (zaddr) start_page;
    range_size = (end_page + page_size) - start_page;

    vm_prot_t prot;
    vm_inherit_t inherit;
    mach_port_t task_self = mach_task_self();

    kern_return_t kr = get_page_info((zaddr) start_page, &prot, &inherit);

    /*
      another method, pelease read `REF`;

     */
    // zpointer code_mmap = mmap(NULL, range_size, PROT_READ | PROT_WRITE,
    //                           MAP_ANON | MAP_SHARED, -1, 0);
    // if (code_mmap == MAP_FAILED) {
    //   return;
    // }

    zpointer code_mmap = zz_alloc_memory(range_size);

    kr = vm_copy(task_self, (zaddr) start_page, range_size,
                 (vm_address_t) code_mmap);

    memcpy(code_mmap + page_offset, code_ptr, code_size);

    /* SAME: mprotect(code_mmap, range_size, prot); */
    zz_mprotect(code_mmap, range_size, prot);

    // TODO: need check `memory region` again.
    /*
        TODO:
        // if only this, `memory region` is `r-x`
        vm_protect((vm_map_t)mach_task_self(), 0x00000001816b2030, 16, false, 0x13);
        // and with this, `memory region` is `rwx`
        *(char *)0x00000001816b01a8 = 'a';
     */

    mach_vm_address_t target = (zaddr) start_page;
    vm_prot_t c, m;
    mach_vm_remap(mach_task_self(), &target, range_size, 0, VM_FLAGS_OVERWRITE,
                  task_self, (mach_vm_address_t) code_mmap, /*copy*/ TRUE, &c, &m,
                  inherit);

    /*
      read `REF`
     */
    // munmap(code_mmap, range_size);
    mach_vm_deallocate(mach_task_self(), (zaddr) code_mmap, range_size);
}
