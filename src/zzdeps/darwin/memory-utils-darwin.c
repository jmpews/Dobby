#include <errno.h>
#include <sys/mman.h>

// for : getpagesize,
#include <unistd.h>

// for : vm_read_overwrite
#include <mach/vm_map.h>

#include "../common/debugbreak.h"
#include "memory-utils-darwin.h"
#include "../posix/memory-utils-posix.h"

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
        KR_ERROR_AT(kr, address);
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