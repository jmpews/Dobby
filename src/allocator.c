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

#include "allocator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ZzAllocator *g_allocator = NULL;

#define DEFAULT_ALLOCATOR_CAPACITY 4

// bad code-style ?
ZzMemoryPage *ZzAllocatorNewMemoryPage() {
  zsize page_size = zz_vm_get_page_size();
  zpointer page_ptr;
  zpointer cave_ptr;
  zpointer case_size;
  page_ptr = zz_vm_allocate_pages(1);
  if (!page_ptr) {
    return NULL;
  }

  if (!zz_vm_protect_as_executable((zaddr)page_ptr, page_size)) {
    Xerror("zz_vm_protect_as_executable error at %p", page_ptr);
    exit(1);
  }

  ZzMemoryPage *page = (ZzMemoryPage *)malloc(sizeof(ZzMemoryPage));
  page->base = page_ptr;
  page->curr_pos = page_ptr;
  page->size = page_size;
  page->used_size = 0;
  return page;
}

ZzMemoryPage *ZzAllocatorNewNearMemoryPage(zaddr address, zsize range_size) {
  zsize page_size = zz_vm_get_page_size();
  zpointer page_ptr;
  zpointer cave_ptr;
  zpointer case_size;
  page_ptr = zz_vm_allocate_near_pages(address, range_size, 1);
  if (!page_ptr) {
    return NULL;
  }

  if (!zz_vm_protect_as_executable((zaddr)page_ptr, page_size)) {
    Xerror("zz_vm_protect_as_executable error at %p", page_ptr);
    exit(1);
  }

  ZzMemoryPage *page = (ZzMemoryPage *)malloc(sizeof(ZzMemoryPage));
  page->base = page_ptr;
  page->curr_pos = page_ptr;
  page->size = page_size;
  page->used_size = 0;
  page->isCodeCave = false;
  return page;
}

ZzMemoryPage *ZzAllocatorNewNearCodeCave(zaddr address, zsize range_size, zsize codeslice_size) {
  zsize page_size = zz_vm_get_page_size();
  zpointer cave_ptr;
  zsize cave_size = codeslice_size;

  cave_ptr = zz_vm_search_text_code_cave(address, range_size, cave_size);

  if (!cave_ptr)
    return NULL;

  ZzMemoryPage *page = (ZzMemoryPage *)malloc(sizeof(ZzMemoryPage));
  page->base = cave_ptr;
  page->curr_pos = cave_ptr;
  page->size = cave_size;
  page->used_size = 0;
  page->isCodeCave = true;
  return page;
}

void ZzAllocatorInitialize() {
  if (!g_allocator) {
    g_allocator = (ZzAllocator *)malloc(sizeof(ZzAllocator));
    memset(g_allocator, 0, sizeof(ZzAllocator));

    g_allocator->memory_pages = (ZzMemoryPage **)malloc(
        sizeof(ZzMemoryPage *) * DEFAULT_ALLOCATOR_CAPACITY);
    memset(g_allocator->memory_pages, 0,
           sizeof(ZzMemoryPage *) * DEFAULT_ALLOCATOR_CAPACITY);

    g_allocator->size = 0;
    g_allocator->capacity = DEFAULT_ALLOCATOR_CAPACITY;
  }
}

//  1. try allocate from the history pages
//  2. try allocate a new page
//  3. add it to the page manager

// can just replace it with `ZzAllocatorNewNearCodeSlice(0, 0, codeslice_size`
ZzCodeSlice *ZzAllocatorNewCodeSlice(zsize codeslice_size) {
  ZzCodeSlice *codeslice;
  if (!g_allocator)
    ZzAllocatorInitialize();

  for (int i = 0; i < g_allocator->size; i++) {
    ZzMemoryPage *page = g_allocator->memory_pages[i];
    // 1. page is initialized
    // 2. can't be codecave
    // 3. the rest memory of this page is enough for codeslice_size
    // 4. the page address is near
    if (page->base && !page->isCodeCave && (page->size - page->used_size) > codeslice_size) {
        codeslice = (ZzCodeSlice *)malloc(sizeof(ZzCodeSlice));
        codeslice->data = page->curr_pos;
        codeslice->size = codeslice_size;

        page->curr_pos += codeslice_size;
        page->used_size += codeslice_size;
        return codeslice;
    }
  }

  if (g_allocator->size >= g_allocator->capacity) {
    ZzMemoryPage **p =
        realloc(g_allocator->memory_pages,
                sizeof(ZzMemoryPage) * (g_allocator->capacity) * 2);
    if (NULL == p) {
      return NULL;
    }
    g_allocator->capacity = g_allocator->capacity * 2;
    g_allocator->memory_pages = p;
  }

  ZzMemoryPage *page;
  page = ZzAllocatorNewMemoryPage();

  g_allocator->memory_pages[g_allocator->size] = page;
  g_allocator->size++;

  codeslice = (ZzCodeSlice *)malloc(sizeof(ZzCodeSlice));
  codeslice->data = page->curr_pos;
  codeslice->size = codeslice_size;

  page->curr_pos += codeslice_size;
  page->used_size += codeslice_size;

  return codeslice;
}


//  1. try allocate from the history pages
//  2. try allocate a new near page
//  3. add it to the page manager

ZzCodeSlice *ZzAllocatorNewNearCodeSlice(zaddr address, zsize range_size,
                                     zsize codeslice_size) {
  ZzCodeSlice *codeslice;
  if (!g_allocator)
    ZzAllocatorInitialize();

  for (int i = 0; i < g_allocator->size; i++) {
    ZzMemoryPage *page = g_allocator->memory_pages[i];
    // 1. page is initialized
    // 2. can't be codecave
    // 3. the rest memory of this page is enough for codeslice_size
    // 4. the page address is near
    if (page->base && !page->isCodeCave && (page->size - page->used_size) > codeslice_size) {
      if (!address ||
          (address && (address - (zaddr)page->curr_pos) < range_size)) {
        codeslice = (ZzCodeSlice *)malloc(sizeof(ZzCodeSlice));
        codeslice->isCodeCave = page->isCodeCave;
        codeslice->data = page->curr_pos;
        codeslice->size = codeslice_size;

        page->curr_pos += codeslice_size;
        page->used_size += codeslice_size;
        return codeslice;
      }
    }
  }

  if (g_allocator->size >= g_allocator->capacity) {
    ZzMemoryPage **p =
        realloc(g_allocator->memory_pages,
                sizeof(ZzMemoryPage) * (g_allocator->capacity) * 2);
    if (NULL == p) {
      return NULL;
    }
    g_allocator->capacity = g_allocator->capacity * 2;
    g_allocator->memory_pages = p;
  }

  ZzMemoryPage *page;
  if (address) {
    page = ZzAllocatorNewNearMemoryPage(address, range_size);
    if (!page) {
      page = ZzAllocatorNewNearCodeCave(address, range_size, codeslice_size);
      if (!page)
        return NULL;
    }
  } else {
    page = ZzAllocatorNewMemoryPage();
  }
  g_allocator->memory_pages[g_allocator->size] = page;
  g_allocator->size++;

  codeslice = (ZzCodeSlice *)malloc(sizeof(ZzCodeSlice));
  codeslice->isCodeCave = page->isCodeCave;
  codeslice->data = page->curr_pos;
  codeslice->size = codeslice_size;

  page->curr_pos += codeslice_size;
  page->used_size += codeslice_size;

  return codeslice;
}
