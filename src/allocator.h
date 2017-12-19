#ifndef allocator_h
#define allocator_h

#include <stdint.h>

#include "hookzz.h"
#include "kitzz.h"

#include "CommonKit/log/log_kit.h"

#include "memory.h"

typedef struct _codeslice {
    zz_ptr_t data;
    zz_size_t size;
    bool is_used;
    bool isCodeCave;
} ZzCodeSlice;

typedef struct _ZzMemoryPage {
    zz_ptr_t base;
    zz_ptr_t curr_pos;
    zz_size_t size;
    zz_size_t used_size;
    bool isCodeCave;
} ZzMemoryPage;

typedef struct _allocator {
    ZzMemoryPage **memory_pages;
    zz_size_t size;
    zz_size_t capacity;
} ZzAllocator;

ZzCodeSlice *ZzNewNearCodeSlice(ZzAllocator *allocator, zz_addr_t address, zz_size_t redirect_range_size,
                                zz_size_t codeslice_size);

ZzCodeSlice *ZzNewCodeSlice(ZzAllocator *allocator, zz_size_t codeslice_size);

ZzAllocator *ZzNewAllocator();

#endif