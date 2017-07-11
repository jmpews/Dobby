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

#include <stdio.h>
#include <stdlib.h>
#include <mach/vm_statistics.h>
#include <sys/mman.h>
#include "allocator.h"

ZZAllocator *g_allocator;

#define DEFAULT_ALLOCATOR_CAPACITY 4

/*
    TODO:
    different from ZZHookFunctionEntry. 
    ZZHookFunctionEntry:
        (ZZHookFunctionEntry **)malloc(...)
    ZZCodeSlice:
        (ZZCodeSlice *)malloc(...)

 */
void ZZAllocatorInitialize() {
    if(!g_allocator) {
        g_allocator = (ZZAllocator *)malloc(sizeof(ZZAllocator));
        g_allocator->codeslices = (ZZCodeSlice *)malloc(sizeof(ZZCodeSlice) * DEFAULT_ALLOCATOR_CAPACITY);
        g_allocator->size = 0;
        g_allocator->capacity = DEFAULT_ALLOCATOR_CAPACITY;
    }
}

/*
    TODO:
    NO USED!!!
    change to `alloc_codeslice(ZZCodeSlice *codeslice)` ?
 */
void alloc_codeslice(ZZCodeSlice *codeslice, zsize codeslice_size)
{
    zpointer page_ptr;
    zsize page_size = codeslice_size;
    page_ptr = alloc_page(page_size);

    codeslice->data = page_ptr;
    codeslice->size = page_size;
    codeslice->is_used = true;
}

/*
    TODO:
    different from `AddHookEntry`:
 */
ZZCodeSlice *ZZAllocatorNewCodeSlice(zsize codeslice_size) {
    if(!g_allocator)
        ZZAllocatorInitialize();

    if(g_allocator->size >= g_allocator->capacity) {
        ZZCodeSlice *p = realloc(g_allocator->codeslices, sizeof(ZZCodeSlice) * (g_allocator->capacity) * 2);
        if(NULL == p)
        {
            return NULL;
        }
        g_allocator->capacity = g_allocator->capacity * 2;
        g_allocator->codeslices = p;
    }

    ZZCodeSlice *pp = &(g_allocator->codeslices[g_allocator->size++]);
    zpointer page_ptr = alloc_page(codeslice_size);
    pp->data = page_ptr;
    pp->size = codeslice_size;
    pp->is_used = true;
    
    return pp;
}

