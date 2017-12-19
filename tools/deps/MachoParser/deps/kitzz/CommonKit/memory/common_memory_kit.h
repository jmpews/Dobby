#ifndef commonkit_memory_memory_kit
#define commonkit_memory_memory_kit

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "kitzz.h"

#include "CommonKit/log/log_kit.h"

typedef struct _MemoryLayout {
    int size;
    struct {
        int flags;
        zz_ptr_t start;
        zz_ptr_t end;
    } mem[4096];
} MemoryLayout;

void *zz_malloc_with_zero(zz_size_t size);

char *zz_vm_read_string(const zz_ptr_t address);

zz_ptr_t zz_vm_search_data(const zz_ptr_t start_addr, const zz_ptr_t end_addr, char *data, zz_size_t data_len);

zz_addr_t zz_vm_align_floor(zz_addr_t address, zz_size_t range_size);

zz_addr_t zz_vm_align_ceil(zz_addr_t address, zz_size_t range_size);

#endif