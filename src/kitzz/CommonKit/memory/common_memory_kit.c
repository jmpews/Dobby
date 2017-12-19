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

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "CommonKit/memory/common_memory_kit.h"

char *zz_vm_read_string(const zz_ptr_t address) {
    const char *start_addr = (const char *)address;
    zz_size_t string_limit = 1024;
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
        memcpy(result, (const zz_ptr_t)start_addr, i + 1);
        return result;
    }
}

zz_ptr_t zz_vm_search_data(const zz_ptr_t start_addr, zz_ptr_t end_addr, char *data, zz_size_t data_len) {
    zz_ptr_t curr_addr;
    if (start_addr <= 0)
        ZZ_ERROR_LOG("search address start_addr(%p) < 0", (zz_ptr_t)start_addr);
    if (start_addr > end_addr)
        ZZ_ERROR_LOG("search start_add(%p) < end_addr(%p)", (zz_ptr_t)start_addr, (zz_ptr_t)end_addr);

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