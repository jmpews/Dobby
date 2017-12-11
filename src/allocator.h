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

#ifndef allocator_h
#define allocator_h

#include <stdint.h>

#include "hookzz.h"
#include "kitzz.h"

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