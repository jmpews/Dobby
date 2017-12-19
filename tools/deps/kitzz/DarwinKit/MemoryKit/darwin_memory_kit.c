#include <errno.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <sys/mman.h>

// for : getpagesize,
#include <unistd.h>

// for : vm_read_overwrite
#include <mach/vm_map.h>

#include "DarwinKit/MemoryKit/darwin_memory_kit.h"

bool zz_vm_read_data_via_task(task_t task, zz_addr_t address, zz_ptr_t buffer, zz_size_t length) {
    vm_size_t n;

    if (address <= 0 || length <= 0) {
        return FALSE;
    }

    kern_return_t kr = vm_read_overwrite((vm_map_t)task, (vm_address_t)address, (vm_size_t)length, (vm_address_t)buffer,
                                         (vm_size_t *)&n);

    if (kr != KERN_SUCCESS) {
        // KR_ERROR_AT(kr, address);
        return FALSE;
    }
    if (length != n) {
        return FALSE;
    }

    return TRUE;
}

char *zz_vm_read_string_via_task(task_t task, zz_addr_t address) {
    char end_c = '\0';
    unsigned long end_addr;
    char *result = NULL;

    // string upper limit 0x1000
    end_addr = zz_vm_search_data_via_task(task, address, address + 0x1000, &end_c, 1);
    if (!end_addr) {
        return NULL;
    }
    result = (char *)malloc(end_addr - address + 1);
    if (result && zz_vm_read_data_via_task(task, address, result, end_addr - address + 1)) {
        return result;
    }
    return NULL;
}

zz_addr_t zz_vm_search_data_via_task(task_t task, zz_addr_t start_addr, zz_addr_t end_addr, char *data,
                                     zz_size_t data_len) {
    unsigned long curr_addr;
    char *temp_buf;
    if (start_addr <= 0 || start_addr > end_addr) {
        return 0;
    }

    // ZZ_ERROR_LOG("search address start_addr(%p) < 0", (zz_ptr_t)start_addr);
    // ZZ_ERROR_LOG("search start_add(%p) < end_addr(%p)", (zz_ptr_t)start_addr, (zz_ptr_t)end_addr);

    curr_addr = start_addr;
    temp_buf  = (char *)malloc(data_len);

    while (end_addr > curr_addr) {
        if (zz_vm_read_data_via_task(task, curr_addr, temp_buf, data_len))
            if (!memcmp(temp_buf, data, data_len)) {
                return curr_addr;
            }
        curr_addr += data_len;
    }
    return 0;
}

bool zz_vm_check_address_valid_via_task(task_t task, const zz_addr_t address) {
    if (address <= 0)
        return FALSE;
#define CHECK_LENGTH 1
    char n_read_bytes[1];
    vm_size_t length;
    kern_return_t kr =
        vm_read_overwrite(task, (vm_address_t)address, CHECK_LENGTH, (vm_address_t)&n_read_bytes, &length);

    if (kr != KERN_SUCCESS || length != CHECK_LENGTH) {
        ZZ_KR_ERROR_LOG(kr);
        return FALSE;
    }
    return TRUE;
}

bool zz_vm_get_page_info_via_task(task_t task, const zz_addr_t address, vm_prot_t *prot_p, vm_inherit_t *inherit_p) {

    vm_address_t region  = (vm_address_t)address;
    vm_size_t region_len = 0;
    struct vm_region_submap_short_info_64 info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t max_depth               = 99999;
    kern_return_t kr;
    kr = vm_region_recurse_64(task, &region, &region_len, &max_depth, (vm_region_recurse_info_t)&info, &info_count);
    if (kr != KERN_SUCCESS) {
        ZZ_KR_ERROR_LOG(kr);
        return FALSE;
    }
    *prot_p    = info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC);
    *inherit_p = info.inheritance;
    return TRUE;
}

bool zz_vm_protect_via_task(task_t task, const zz_addr_t address, zz_size_t size, vm_prot_t page_prot) {
    kern_return_t kr;
    vm_size_t page_size;
    vm_address_t aligned_addr;
    vm_size_t aligned_size;

    page_size    = zz_posix_vm_get_page_size();
    aligned_addr = address & ~(page_size - 1);
    aligned_size = (1 + ((address + size - 1 - aligned_addr) / page_size)) * page_size;

    kr = mach_vm_protect(task, aligned_addr, aligned_size, FALSE, page_prot);
    if (kr != KERN_SUCCESS) {
        ZZ_KR_ERROR_LOG(kr);
        return FALSE;
    }
    return TRUE;
}

bool zz_vm_protect_as_executable_via_task(task_t task, const zz_addr_t address, zz_size_t size) {
    return zz_vm_protect_via_task(task, address, size, (VM_PROT_READ | VM_PROT_EXECUTE));
}

bool zz_vm_protect_as_writable_via_task(task_t task, const zz_addr_t address, zz_size_t size) {
    if (!zz_vm_protect_via_task(task, address, size, (VM_PROT_ALL | VM_PROT_COPY))) {
        return zz_vm_protect_via_task(task, address, size, (VM_PROT_DEFAULT | VM_PROT_COPY));
    }
    return FALSE;
}

zz_ptr_t zz_vm_allocate_pages_via_task(task_t task, zz_size_t n_pages) {
    vm_address_t result;
    kern_return_t kr;
    vm_size_t page_size;
    page_size = zz_posix_vm_get_page_size();

    if (n_pages <= 0) {
        n_pages = 1;
    }

    kr = mach_vm_allocate(task, (mach_vm_address_t *)&result, page_size * n_pages, VM_FLAGS_ANYWHERE);

    if (kr != KERN_SUCCESS) {
        ZZ_KR_ERROR_LOG(kr);
        return NULL;
    }

    if (!zz_vm_protect_via_task(task, result, page_size * n_pages, (VM_PROT_DEFAULT | VM_PROT_COPY)))
        return NULL;

    return (zz_ptr_t)result;
}

// try to allocate a rx page
bool zz_vm_can_allocate_rx_page() {
    vm_prot_t prot;
    vm_inherit_t inherit;
    kern_return_t kr;
    mach_port_t task_self = mach_task_self();
    mach_vm_address_t result;

    vm_address_t temp_page_addr = (vm_address_t)zz_vm_allocate_pages_via_task(mach_task_self(), 1);
    zz_vm_protect_as_executable_via_task(mach_task_self(), temp_page_addr, zz_posix_vm_get_page_size());

    if (!zz_vm_get_page_info_via_task(task_self, temp_page_addr, &prot, &inherit)) {
        return FALSE;
    }

    kr = mach_vm_deallocate(task_self, temp_page_addr, zz_posix_vm_get_page_size());

    if (kr != KERN_SUCCESS) {
        ZZ_KR_ERROR_LOG(kr);
        return FALSE;
    }
    if (prot & VM_PROT_EXECUTE) {
        return TRUE;
    }
    return FALSE;
}

zz_ptr_t zz_vm_allocate_via_task(task_t task, zz_size_t size) {
    vm_size_t page_size, n_pages;
    void *result;

    page_size = zz_posix_vm_get_page_size();
    n_pages   = ((size + page_size - 1) & ~(page_size - 1)) / page_size;

    result = zz_vm_allocate_pages_via_task(task, n_pages);
    return result;
}

zz_ptr_t zz_vm_allocate_near_pages_via_task(task_t task, zz_addr_t address, zz_size_t range_size, zz_size_t n_pages) {
    mach_vm_address_t aligned_addr, tmp_addr;
    kern_return_t kr;
    vm_size_t page_size;

    page_size = zz_posix_vm_get_page_size();

    if (n_pages <= 0) {
        n_pages = 1;
    }

    aligned_addr                   = address & ~(page_size - 1);
    vm_address_t target_start_addr = zz_vm_align_floor(address - range_size, page_size);
    vm_address_t target_end_addr   = zz_vm_align_floor(address + range_size, page_size);

    for (tmp_addr = target_start_addr; tmp_addr < target_end_addr; tmp_addr += page_size) {
        kr = mach_vm_allocate(task, &tmp_addr, page_size * n_pages, VM_FLAGS_FIXED);
        if (kr == KERN_SUCCESS) {
            return (void *)tmp_addr;
        }
    }
    return NULL;
}

zz_ptr_t zz_vm_search_text_code_cave_via_task(task_t task, zz_addr_t address, zz_size_t range_size,
                                              zz_size_t *size_ptr) {
    char zeroArray[128];
    char readZeroArray[128];
    vm_address_t aligned_addr, tmp_addr, target_search_start, target_search_end;
    kern_return_t kr;
    vm_size_t page_size;

    memset(zeroArray, 0, 128);

    page_size           = zz_posix_vm_get_page_size();
    aligned_addr        = address & ~(page_size - 1);
    target_search_start = aligned_addr - range_size;
    target_search_end   = aligned_addr + range_size;

    ZZ_DEBUG_LOG("searching for %p cave...", (zz_ptr_t)address);
    // TODO: check the memory region attributes
    for (tmp_addr = target_search_start; tmp_addr < target_search_end; tmp_addr += 0x1000) {
        if (zz_vm_read_data_via_task(task, tmp_addr, readZeroArray, 128)) {
            if (!memcmp(readZeroArray, zeroArray, 128)) {
                *size_ptr = 0x1000;
                ZZ_DEBUG_LOG("found a cave at %p, size %d", (void *)tmp_addr, 0x1000);
                return (void *)tmp_addr;
            }
        }
    }
    return NULL;
}

MemoryLayout *zz_vm_get_memory_layout_via_task(task_t task) {
    mach_msg_type_number_t count;
    struct vm_region_submap_info_64 info;
    vm_size_t nesting_depth;

    kern_return_t kr         = KERN_SUCCESS;
    vm_address_t address_tmp = 0;
    vm_size_t size_tmp       = 0;

    MemoryLayout *mlayout = (MemoryLayout *)malloc(sizeof(MemoryLayout));
    memset(mlayout, 0, sizeof(MemoryLayout));

    while (1) {
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr    = vm_region_recurse_64(task, &address_tmp, &size_tmp, (natural_t *)&nesting_depth,
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
            address_tmp += size_tmp;

            mlayout->mem[mlayout->size].start   = (void *)(address_tmp - size_tmp);
            mlayout->mem[mlayout->size].end     = (void *)address_tmp;
            mlayout->mem[mlayout->size++].flags = ((info.protection & PROT_READ) ? (1 << 0) : 0) |
                                                  ((info.protection & PROT_WRITE) ? (1 << 1) : 0) |
                                                  ((info.protection & PROT_EXEC) ? (1 << 2) : 0);
        }
    }
    return mlayout;
}

// https://github.com/kpwn/935csbypass/blob/master/cs_bypass.m
zz_ptr_t zz_vm_search_code_cave(zz_addr_t address, zz_size_t range_size, zz_size_t size) {
    char zeroArray[128];
    char readZeroArray[128];
    vm_address_t aligned_addr, tmp_addr, search_start, search_end, search_start_limit, search_end_limit;
    vm_size_t page_size;

    void *result_ptr;
    memset(zeroArray, 0, 128);

    search_start_limit = address - range_size;
    search_end_limit   = address + range_size;

    MemoryLayout *mlayout = zz_vm_get_memory_layout_via_task(mach_task_self());

    int i;
    for (i = 0; i < mlayout->size; i++) {
        if (mlayout->mem[i].flags == (1 << 0 | 1 << 2)) {
            search_start = (vm_address_t)mlayout->mem[i].start;
            search_end   = (vm_address_t)mlayout->mem[i].end;

            if (search_start < search_start_limit) {

                if (search_end > search_start_limit && search_end < search_end_limit) {
                    search_start = search_start_limit;
                } else if (search_end > search_end_limit) {
                    search_start = search_start_limit;
                    search_end   = search_end_limit;
                } else {
                    continue;
                }
            } else if (search_start >= search_start_limit && search_start <= search_end_limit) {
                if (search_end > search_start_limit && search_end < search_end_limit) {
                } else if (search_end > search_end_limit) {
                    search_end = search_end_limit;
                } else {
                    continue;
                }
            } else {
                continue;
            }

            result_ptr = zz_vm_search_data((void *)search_start, (void *)search_end, (char *)zeroArray, size);
            if (result_ptr) {
                free(mlayout);
                return result_ptr;
            }
        }
    }
    free(mlayout);
    return NULL;
}

// TODO: vm_region_recurse_64 is better ?
zz_ptr_t zz_vm_search_text_code_cave_via_dylibs(zz_addr_t address, zz_size_t range_size, zz_size_t size) {
    char zeroArray[128];
    char readZeroArray[128];
    vm_address_t aligned_addr, tmp_addr, search_start, search_end, search_start_limit, search_end_limit;
    vm_size_t page_size;

    zz_ptr_t result_ptr;

    memset(zeroArray, 0, 128);

    page_size          = zz_posix_vm_get_page_size();
    search_start_limit = address - range_size;
    search_end_limit   = address + range_size;

    zz_size_t n_dylibs = _dyld_image_count();
    for (size_t i = 0; i < n_dylibs; i++) {
        struct mach_header_64 *header         = (struct mach_header_64 *)_dyld_get_image_header(i);
        struct segment_command_64 *seg_cmd_64 = zz_macho_get_segment_64_via_name(header, "__TEXT");

        // ATTENTION: as the __TEXT segment region is 'r-x', diffrent from
        // others, so it's page align.
        search_start = (zz_addr_t)header;
        // no need align again.
        search_start = zz_vm_align_floor(search_start, page_size);
        search_end   = (zz_addr_t)header + seg_cmd_64->vmsize;
        // no need align again.
        search_end = zz_vm_align_ceil(search_end, page_size);

        if (search_start < search_start_limit) {

            if (search_end > search_start_limit && search_end < search_end_limit) {
                search_start = search_start_limit;
            } else if (search_end > search_end_limit) {
                search_start = search_start_limit;
                search_end   = search_end_limit;
            } else {
                continue;
            }
        } else if (search_start >= search_start_limit && search_start <= search_end_limit) {
            if (search_end > search_start_limit && search_end < search_end_limit) {
            } else if (search_end > search_end_limit) {
                search_end = search_end_limit;
            } else {
                continue;
            }
        } else {
            continue;
        }

        result_ptr = zz_vm_search_data((void *)search_start, (void *)search_end, (char *)zeroArray, size);
        if (result_ptr) {
            return result_ptr;
        }
    }
    return NULL;
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

bool zz_vm_patch_code_via_task(task_t task, const zz_addr_t address, const zz_ptr_t codedata, zz_size_t codedata_size) {
    vm_address_t start_page_addr, end_page_addr;
    vm_size_t page_offset, range_size, page_size;

    page_size = zz_posix_vm_get_page_size();

    /*
      https://www.gnu.org/software/hurd/gnumach-doc/Memory-Attributes.html
     */
    start_page_addr = address & ~(page_size - 1);
    end_page_addr   = (address + codedata_size - 1) & ~(page_size - 1);
    page_offset     = address - start_page_addr;
    range_size      = (end_page_addr + page_size) - start_page_addr;

    vm_prot_t prot;
    vm_inherit_t inherit;
    kern_return_t kr;
    mach_port_t task_self = mach_task_self();

    if (!zz_vm_get_page_info_via_task(task_self, (const zz_addr_t)start_page_addr, &prot, &inherit)) {
        return FALSE;
    }

    /*
      another method, pelease read `REF`;

     */
    // zz_ptr_t code_mmap = mmap(NULL, range_size, PROT_READ | PROT_WRITE,
    //                           MAP_ANON | MAP_SHARED, -1, 0);
    // if (code_mmap == MAP_FAILED) {
    //   return;
    // }

    void *code_mmap = zz_vm_allocate_via_task(task_self, range_size);

    kr = vm_copy(task_self, start_page_addr, range_size, (vm_address_t)code_mmap);

    if (kr != KERN_SUCCESS) {
        ZZ_KR_ERROR_LOG(kr);
        return FALSE;
    }
    memcpy(code_mmap + page_offset, codedata, codedata_size);

    /* SAME: mprotect(code_mmap, range_size, prot); */
    if (!zz_vm_protect_via_task(task_self, (zz_addr_t)code_mmap, range_size, prot))
        return FALSE;

    // TODO: need check `memory region` again.
    /*
        TODO:
        // if only this, `memory region` is `r-x`
        vm_protect((vm_map_t)mach_task_self(), 0x00000001816b2030, 16, FALSE,
       0x13);
        // and with this, `memory region` is `rwx`
        *(char *)0x00000001816b01a8 = 'a';
     */

    mach_vm_address_t target = start_page_addr;
    vm_prot_t c, m;
    kr = mach_vm_remap(task_self, &target, range_size, 0, VM_FLAGS_OVERWRITE, task_self, (mach_vm_address_t)code_mmap,
                       /*copy*/ TRUE, &c, &m, inherit);

    if (kr != KERN_SUCCESS) {
        ZZ_KR_ERROR_LOG(kr);
        return FALSE;
    }
    /*
      read `REF`
     */
    // munmap(code_mmap, range_size);
    kr = mach_vm_deallocate(task_self, (mach_vm_address_t)code_mmap, range_size);
    if (kr != KERN_SUCCESS) {
        ZZ_KR_ERROR_LOG(kr);
        return FALSE;
    }
    return TRUE;
}
