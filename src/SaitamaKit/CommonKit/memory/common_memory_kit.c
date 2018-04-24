#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "CommonKit/log/log_kit.h"
#include "CommonKit/memory/common_memory_kit.h"

char *zz_vm_read_string(const char *address) {
    const char *start_addr = (const char *)address;
    zz_size_t string_limit = 1024;
    zz_size_t i;
    char *result;

    for (i = 0; i < string_limit; i++) {
        if (*(start_addr + i) == '\0')
            break;
    }
    if (i == string_limit)
        return NULL;
    else {
        result = (char *)malloc(i + 1);
        if (!result) {
            COMMON_ERROR_LOG();
        }
        memcpy(result, (const zz_ptr_t)start_addr, i + 1);
        return result;
    }
}

zz_ptr_t zz_vm_search_data(const zz_ptr_t start_addr, zz_ptr_t end_addr, char *data, zz_size_t data_len) {
    zz_ptr_t curr_addr;
    if (start_addr <= 0)
        ERROR_LOG("search address start_addr(%p) < 0", (zz_ptr_t)start_addr);
    if (start_addr > end_addr)
        ERROR_LOG("search start_add(%p) < end_addr(%p)", (zz_ptr_t)start_addr, (zz_ptr_t)end_addr);

    curr_addr = start_addr;

    while (end_addr > curr_addr) {
        if (!memcmp(curr_addr, data, data_len)) {
            return curr_addr;
        }
        curr_addr += data_len;
    }
    return 0;
}

zz_addr_t zz_vm_align_floor(zz_addr_t address, zz_size_t range_size) {
    zz_addr_t result;
    result = address & ~(range_size - 1);
    return result;
}

zz_addr_t zz_vm_align_ceil(zz_addr_t address, zz_size_t range_size) {
    zz_addr_t result;
    result = (address + range_size - 1) & ~(range_size - 1);
    return result;
}