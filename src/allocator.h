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

#include "zz.h"
#include "../include/hookzz.h"
#include <stdint.h>

#if defined(__x86_64__)
#include "platforms/darwin/memory-darwin.h"
#elif defined(__arm64__)
#include "platforms/darwin/memory-darwin.h"
#endif

typedef struct _codeslice
{
    zpointer data;
    zsize size;
    bool is_used;
} ZZCodeSlice;

typedef struct _allocator {
    ZZCodeSlice *codeslices;
    zsize size;
    zsize capacity;  
} ZZAllocator;

ZZCodeSlice *ZZAllocatorNewCodeSlice(zsize codeslice_size);

#endif