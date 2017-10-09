
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
// for : getpagesize,
#include <unistd.h>

#include "memory-utils-common.h"

char *zz_vm_read_string(const zpointer address) {
    const char *start_addr = (const char *)address;
    unsigned int string_limit = 1024;
    unsigned int i;
    char *result;

    for (i = 0; i < string_limit; i++) {
        if (*(start_addr + i) == '\0')
            break;
    }
    if (i == string_limit)
        return NULL;
    else {
        result = (char *)malloc(i + 1);
        memcpy(result, (const zpointer)start_addr, i + 1);
        return result;
    }
}

zpointer zz_vm_search_data(const zpointer start_addr, zpointer end_addr, zbyte *data,
                           zsize data_len) {
    zpointer curr_addr;
    if (start_addr <= 0)
        Xerror("search address start_addr(%p) < 0", (zpointer)start_addr);
    if (start_addr > end_addr)
        Xerror("search start_add(%p) < end_addr(%p)", (zpointer)start_addr, (zpointer)end_addr);

    curr_addr = start_addr;

    while (end_addr > curr_addr) {
        if (!memcmp(curr_addr, data, data_len)) {
            return curr_addr;
        }
        curr_addr += data_len;
    }
    return 0;
}

zaddr zz_vm_align_floor(zaddr address, zsize range_size) {
    zaddr result;
    result = address & ~(range_size - 1);
    return result;
}

zaddr zz_vm_align_ceil(zaddr address, zsize range_size) {
    zaddr result;
    result = (address + range_size - 1) & ~(range_size - 1);
    return result;
}