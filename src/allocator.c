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
#include "allocator.h"

ZzAllocator *g_allocator;

#define DEFAULT_ALLOCATOR_CAPACITY 4

// bad code-style ?
void ZzAllocatorInitializeMemoryPage(ZzMemoryPage *memory_page)
{
    zsize page_size = zz_vm_get_page_size();
    zpointer page_ptr = zz_vm_allocate(page_size);
    if (!zz_vm_protect_as_executable((zaddr)page_ptr, page_size))
    {
        Xerror("zz_vm_protect_as_executable error at %p", page_ptr);
        exit(1);
    }
    memory_page->base = page_ptr;
    memory_page->curr_pos = page_ptr;
    memory_page->size = page_size;
    memory_page->used_size = 0;
}

void ZzAllocatorInitialize()
{
    if (!g_allocator)
    {
        g_allocator = (ZzAllocator *)malloc(sizeof(ZzAllocator));
        g_allocator->memory_pages = (ZzMemoryPage *)malloc(sizeof(ZzMemoryPage) * DEFAULT_ALLOCATOR_CAPACITY);
        g_allocator->size = 0;
        g_allocator->capacity = DEFAULT_ALLOCATOR_CAPACITY;
        g_allocator->curr_memory_page = &g_allocator->memory_pages[0];
        for (int i = 0; i < g_allocator->capacity; i++)
        {
            if (!g_allocator->memory_pages[i].base)
            {
                ZzAllocatorInitializeMemoryPage(&g_allocator->memory_pages[i]);
            }
        }
    }
}

/*
    codeslice manager.
 */
ZzCodeSlice *ZzAllocatorNewCodeSlice(zsize codeslice_size)
{
    ZzCodeSlice *codeslice;
    ZzMemoryPage *curr_memory_page;
    if (!g_allocator)
        ZzAllocatorInitialize();

    curr_memory_page = g_allocator->curr_memory_page;

    if (g_allocator->size >= g_allocator->capacity)
    {
        ZzMemoryPage *p = realloc(g_allocator->memory_pages, sizeof(ZzMemoryPage) * (g_allocator->capacity) * 2);
        if (NULL == p)
        {
            return NULL;
        }
        g_allocator->capacity = g_allocator->capacity * 2;
        g_allocator->memory_pages = p;
        for (int i = 0; i < g_allocator->capacity; i++)
        {
            if (!g_allocator->memory_pages[i].base)
            {
                ZzAllocatorInitializeMemoryPage(&g_allocator->memory_pages[i]);
            }
        }
    }

    // check the memory-page remain.
    if (curr_memory_page->size - curr_memory_page->used_size < codeslice_size)
    {
        g_allocator->size++;
        g_allocator->curr_memory_page = &g_allocator->memory_pages[g_allocator->size];
        curr_memory_page = g_allocator->curr_memory_page;
    }

    codeslice = (ZzCodeSlice *)malloc(sizeof(ZzCodeSlice));
    codeslice->data = curr_memory_page->curr_pos;
    codeslice->size = codeslice_size;

    curr_memory_page->curr_pos += codeslice_size;
    curr_memory_page->used_size += codeslice_size;

    return codeslice;
}
