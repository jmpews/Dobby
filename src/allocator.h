//    Copyright 2017 jmpews
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

#ifndef allocator_h
#define allocator_h

#include <stdint.h>

#include "hookzz.h"
#include "memory.h"

typedef struct _codeslice {
    zpointer data;
    zsize size;
    zboolis_used;
    zboolisCodeCave;
} ZzCodeSlice;

typedef struct _ZzMemoryPage {
    zpointer base;
    zpointer curr_pos;
    zsize size;
    zsize used_size;
    zboolisCodeCave;
} ZzMemoryPage;

typedef struct _allocator {
    ZzMemoryPage **memory_pages;
    zsize size;
    zsize capacity;
} ZzAllocator;

ZzCodeSlice *ZzNewNearCodeSlice(ZzAllocator *allocator, zaddr address, zsize range_size, zsize codeslice_size);

ZzCodeSlice *ZzNewCodeSlice(ZzAllocator *allocator, zsize codeslice_size);

ZzAllocator *ZzNewAllocator();

#endif