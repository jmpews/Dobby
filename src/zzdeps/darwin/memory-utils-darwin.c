#include <errno.h>
#include <sys/mman.h>

#include <mach/mach.h>
#include <mach-o/dyld.h>

// for : getpagesize,
#include <unistd.h>

// for : vm_read_overwrite
#include <mach/vm_map.h>

#include "../common/debugbreak.h"
#include "../common/memory-utils-common.h"
#include "memory-utils-darwin.h"
#include "../posix/memory-utils-posix.h"
#include "macho-utils-darwin.h"

// --- about read function ---

bool zz_vm_read_data_via_task(task_t task, const zaddr address, zpointer buffer,
                              zsize length)
{
    vm_size_t dataCnt;
    dataCnt = 0;
    if (address <= 0)
    {
        Xerror("read address %p< 0", (zpointer)address);
        return false;
    }
    if (length <= 0)
    {
        Xerror("read length %p <0", (zpointer)address);
        return false;
    }
    dataCnt = length;
    kern_return_t kr =
        vm_read_overwrite(task, address, length, (zaddr)buffer, (vm_size_t *)&dataCnt);

    if (kr != KERN_SUCCESS)
    {
        // KR_ERROR_AT(kr, address);
        return false;
    }
    if (length != dataCnt)
    {
        warnx("rt_read size return not match!");
        return false;
    }

    return true;
}

char *zz_vm_read_string_via_task(task_t task, const zaddr address)
{
    char end_c = '\0';
    zaddr end_addr;
    char *result = NULL;

    // string upper limit 0x1000
    end_addr = zz_vm_search_data_via_task(task, address, address + 0x1000, (zbyte *)&end_c, 1);
    if (!end_addr)
    {
        return NULL;
    }
    result = (char *)malloc(end_addr - address + 1);
    if (result && zz_vm_read_data_via_task(task, address, result, end_addr - address + 1))
    {
        return result;
    }
    return NULL;
}

// --- end ---

zaddr zz_vm_search_data_via_task(task_t task, const zaddr start_addr, const zaddr end_addr, zbyte *data,
                                 zsize data_len)
{
    zaddr curr_addr;
    zbyte *temp_buf;
    if (start_addr <= 0)
        Xerror("search address start_addr(%p) < 0", (zpointer)start_addr);
    if (start_addr > end_addr)
        Xerror("search start_add(%p) < end_addr(%p)", (zpointer)start_addr, (zpointer)end_addr);

    curr_addr = (zaddr)start_addr;
    temp_buf = (zbyte *)malloc(data_len);

    while (end_addr > curr_addr)
    {
        if (zz_vm_read_data_via_task(task, curr_addr, temp_buf, data_len))
            if (!memcmp(temp_buf, data, data_len))
            {
                return curr_addr;
            }
        curr_addr += data_len;
    }
    return 0;
}

bool zz_vm_check_address_valid_via_task(task_t task, const zaddr address)
{
    if (address <= 0)
        return false;
#define CHECK_LEN 1
    char n_read_bytes[1];
    zuint len;
    kern_return_t kr = vm_read_overwrite(task, address, CHECK_LEN, (zaddr)&n_read_bytes,
                                         (vm_size_t *)&len);

    if (kr != KERN_SUCCESS || len != CHECK_LEN)
        KR_ERROR_AT(kr, address);
    return false;
    return true;
}

bool zz_vm_get_page_info_via_task(task_t task, const zaddr address, vm_prot_t *prot_p,
                                  vm_inherit_t *inherit_p)
{

    zaddr region = (zaddr)address;
    zsize region_len = 0;
    struct vm_region_submap_short_info_64 info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t max_depth = 99999;
    kern_return_t kr =
        vm_region_recurse_64(task, &region, &region_len, &max_depth,
                             (vm_region_recurse_info_t)&info, &info_count);
    if (kr != KERN_SUCCESS)
    {
        KR_ERROR_AT(kr, address);
        return false;
    }
    *prot_p = info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC);
    *inherit_p = info.inheritance;
    return true;
}

bool zz_vm_protect_via_task(task_t task, const zaddr address, zsize size, vm_prot_t page_prot)
{
    kern_return_t kr;

    zsize page_size;
    zaddr aligned_addr;
    zsize aligned_size;

    page_size = zz_vm_get_page_size();
    aligned_addr = (zaddr)address & ~(page_size - 1);
    aligned_size =
        (1 + ((address + size - 1 - aligned_addr) / page_size)) * page_size;

    kr = mach_vm_protect(task, (vm_address_t)aligned_addr,
                         aligned_size, false, page_prot);
    if (kr != KERN_SUCCESS)
    {
        KR_ERROR_AT(kr, address);
        Xerror("kr = %d, at (%p) error!", kr, (zpointer)address);
        return false;
    }
    return true;
}

bool zz_vm_protect_as_executable_via_task(task_t task, const zaddr address, zsize size)
{
    return zz_vm_protect_via_task(task, address, size, (VM_PROT_READ | VM_PROT_EXECUTE));
}

bool zz_vm_protect_as_writable_via_task(task_t task, const zaddr address, zsize size)
{
    if (!zz_vm_protect_via_task(task, address, size, (VM_PROT_ALL | VM_PROT_COPY)))
    {
        return zz_vm_protect_via_task(task, address, size, (VM_PROT_DEFAULT | VM_PROT_COPY));
    }
    return false;
}

zpointer zz_vm_allocate_pages_via_task(task_t task, zsize n_pages)
{
    mach_vm_address_t result;
    kern_return_t kr;
    zsize page_size;
    page_size = zz_vm_get_page_size();

    if (n_pages <= 0)
    {
        n_pages = 1;
    }

    kr = mach_vm_allocate(task, &result, page_size * n_pages,
                          VM_FLAGS_ANYWHERE);

    if (kr != KERN_SUCCESS)
    {
        KR_ERROR(kr);
        return NULL;
    }

    if (!zz_vm_protect_via_task(task, (zaddr)result, page_size * n_pages, (VM_PROT_DEFAULT | VM_PROT_COPY)))
        return NULL;

    return (zpointer)result;
}


zpointer zz_vm_allocate_via_task(task_t task, zsize size)
{
    zsize page_size;
    zpointer result;
    zsize n_pages;

    page_size = zz_vm_get_page_size();
    n_pages = ((size + page_size - 1) & ~(page_size - 1)) / page_size;

    result = zz_vm_allocate_pages_via_task(task, n_pages);
    return (zpointer)result;
}


zpointer zz_vm_allocate_near_pages_via_task(task_t task, zaddr address, zsize range_size,  zsize n_pages) {
    mach_vm_address_t aligned_addr;
    kern_return_t kr;
    mach_vm_address_t tmp_addr;
    zsize page_size;
    page_size = zz_vm_get_page_size();

    if (n_pages <= 0)
    {
        n_pages = 1;
    }
    aligned_addr = (zaddr)address & ~(page_size - 1);

    vm_address_t target_start_addr = aligned_addr - range_size;
    vm_address_t target_end_addr = aligned_addr + range_size;

    for(tmp_addr = target_start_addr; tmp_addr < target_end_addr; tmp_addr += page_size) {
        kr = mach_vm_allocate(task, &tmp_addr, page_size * n_pages,
            VM_FLAGS_FIXED);    
        if(kr == KERN_SUCCESS) {
            return (zpointer)tmp_addr;
        }
    }
    return NULL;
}

zpointer zz_vm_search_text_code_cave_via_task(task_t task, zaddr address, zsize range_size, zsize *size_ptr) {
    char zeroArray[128];
    char readZeroArray[128];
    mach_vm_address_t aligned_addr, tmp_addr, target_search_start, target_search_end;
    kern_return_t kr;
    zsize page_size;

    memset(zeroArray, 0, 128);

    page_size = zz_vm_get_page_size();
    aligned_addr = (zaddr)address & ~(page_size - 1);
    target_search_start = aligned_addr - range_size;
    target_search_end = aligned_addr + range_size;

    Xdebug("searching for %p cave...", (zpointer)address);
    // TODO: check the memory region attributes
    for(tmp_addr = target_search_start; tmp_addr < target_search_end; tmp_addr += 0x1000) {
        if(zz_vm_read_data_via_task(task, tmp_addr, readZeroArray, 128)) {
            if(!memcmp(readZeroArray, zeroArray, 128)) {
                *size_ptr = 0x1000;
                Xdebug("found a cave at %p, size %d", (zpointer)tmp_addr, 0x1000);
                return (void *)tmp_addr;
            }
        }
    }
    return NULL;
}


zpointer zz_vm_search_text_code_cave_via_dylibs(zaddr address, zsize range_size, zsize size) {
    char zeroArray[128];
    char readZeroArray[128];
    zaddr aligned_addr, tmp_addr, search_start, search_end, search_start_limit, search_end_limit;
    zsize page_size;

    zpointer result_ptr;

    memset(zeroArray, 0, 128);

    page_size = zz_vm_get_page_size();
    search_start_limit = address - range_size;
    search_end_limit = address + range_size;

    zsize n_dylibs = _dyld_image_count();
    for (size_t i = 0; i < n_dylibs; i++)
    {
        struct mach_header_64 *header = (struct mach_header_64 *)_dyld_get_image_header(i);
        struct segment_command_64 *seg_cmd_64 = zz_macho_get_segment_64_via_name(header, "__TEXT");
        
        // ATTENTION: as the __TEXT segment region is 'r-x', diffrent from others, so it's page align.
        search_start = (zaddr)header;
        // no need align again.
        search_start = zz_vm_align_floor(search_start, page_size);
        search_end = (zaddr)header + seg_cmd_64->vmsize;
        // no need align again.
        search_end = zz_vm_align_ceil(search_end, page_size);

        if(search_start < search_start_limit) {
            
            if(search_end > search_start_limit && search_end < search_end_limit) {
                search_start = search_start_limit;
            } else if (search_end > search_end_limit)
            {
                search_start = search_start_limit;
                search_end = search_end_limit;
            } else {
                continue;
            }
        } else if(search_start >= search_start_limit && search_start <= search_end_limit){
            if(search_end > search_start_limit && search_end < search_end_limit) {
            } else if (search_end > search_end_limit)
            {
                search_end = search_end_limit;
            } else {
                continue;
            }
        } else {
            continue;
        }

        result_ptr = zz_vm_search_data((zpointer)search_start, (zpointer)search_end, (zbyte *)zeroArray, size);
        if(result_ptr) {
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

bool zz_vm_patch_code_via_task(task_t task, const zaddr address, const zpointer codedata, zuint codedata_size)
{
    zsize page_size;
    zaddr start_page_addr, end_page_addr;
    zsize page_offset, range_size;

    page_size = zz_vm_get_page_size();
    /*
      https://www.gnu.org/software/hurd/gnumach-doc/Memory-Attributes.html
     */
    start_page_addr = (address) & ~(page_size - 1);
    end_page_addr = ((address + codedata_size - 1)) & ~(page_size - 1);
    page_offset = address - start_page_addr;
    range_size = (end_page_addr + page_size) - start_page_addr;

    vm_prot_t prot;
    vm_inherit_t inherit;
    kern_return_t kr;
    mach_port_t task_self = mach_task_self();

    if (!zz_vm_get_page_info_via_task(task_self, (const zaddr)start_page_addr, &prot, &inherit))
    {
        return false;
    }

    /*
      another method, pelease read `REF`;

     */
    // zpointer code_mmap = mmap(NULL, range_size, PROT_READ | PROT_WRITE,
    //                           MAP_ANON | MAP_SHARED, -1, 0);
    // if (code_mmap == MAP_FAILED) {
    //   return;
    // }

    zpointer code_mmap = zz_vm_allocate_via_task(task_self, range_size);

    kr = vm_copy(task_self, start_page_addr, range_size,
                 (vm_address_t)code_mmap);

    if (kr != KERN_SUCCESS)
    {
        KR_ERROR_AT(kr, start_page_addr);
        return false;
    }
    memcpy(code_mmap + page_offset, codedata, codedata_size);

    /* SAME: mprotect(code_mmap, range_size, prot); */
    if (!zz_vm_protect_via_task(task_self, (zaddr)code_mmap, range_size, prot))
        return false;

    // TODO: need check `memory region` again.
    /*
        TODO:
        // if only this, `memory region` is `r-x`
        vm_protect((vm_map_t)mach_task_self(), 0x00000001816b2030, 16, false, 0x13);
        // and with this, `memory region` is `rwx`
        *(char *)0x00000001816b01a8 = 'a';
     */

    mach_vm_address_t target = (zaddr)start_page_addr;
    vm_prot_t c, m;
    kr = mach_vm_remap(task_self, &target, range_size, 0, VM_FLAGS_OVERWRITE,
                       task_self, (mach_vm_address_t)code_mmap, /*copy*/ true, &c, &m,
                       inherit);

    if (kr != KERN_SUCCESS)
    {
        KR_ERROR(kr);
        return false;
    }
    /*
      read `REF`
     */
    // munmap(code_mmap, range_size);
    kr = mach_vm_deallocate(task_self, (zaddr)code_mmap, range_size);
    if (kr != KERN_SUCCESS)
    {
        KR_ERROR(kr);
        return false;
    }
    return true;
}

