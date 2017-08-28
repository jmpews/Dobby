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

// ZzAllocator *g_allocator = NULL;

#define DEFAULT_ALLOCATOR_CAPACITY 4

ZzAllocator *ZzNewAllocator() {
  ZzAllocator *allocator;
  allocator = (ZzAllocator *)malloc(sizeof(ZzAllocator));
  allocator->memory_pages = (ZzMemoryPage **)malloc(sizeof(ZzMemoryPage *) *
                                                    DEFAULT_ALLOCATOR_CAPACITY);
  if (!allocator->memory_pages)
    return NULL;
  allocator->size = 0;
  allocator->capacity = DEFAULT_ALLOCATOR_CAPACITY;
  return allocator;
}

// bad code-style ?
ZzMemoryPage *ZzNewMemoryPage() {
  zsize page_size = ZzMemoryGetPageSzie();
  zpointer page_ptr;
  zpointer cave_ptr;
  zpointer case_size;
  page_ptr = ZzMemoryAllocatePages(1);
  if (!page_ptr) {
    return NULL;
  }

  if (!ZzMemoryProtectAsExecutable((zaddr)page_ptr, page_size)) {
    Xerror("ZzMemoryProtectAsExecutable error at %p", page_ptr);
    exit(1);
  }

  ZzMemoryPage *page = (ZzMemoryPage *)malloc(sizeof(ZzMemoryPage));
  page->base = page_ptr;
  page->curr_pos = page_ptr;
  page->size = page_size;
  page->used_size = 0;
  return page;
}

ZzMemoryPage *ZzNewNearMemoryPage(zaddr address, zsize range_size) {
  zsize page_size = ZzMemoryGetPageSzie();
  zpointer page_ptr;
  zpointer cave_ptr;
  zpointer case_size;
  page_ptr = ZzMemoryAllocateNearPages(address, range_size, 1);
  if (!page_ptr) {
    return NULL;
  }

  if (!ZzMemoryProtectAsExecutable((zaddr)page_ptr, page_size)) {
    Xerror("ZzMemoryProtectAsExecutable error at %p", page_ptr);
    exit(1);
  }

  ZzMemoryPage *page = (ZzMemoryPage *)malloc(sizeof(ZzMemoryPage));
  page->base = page_ptr;
  if ((zaddr)page_ptr > address &&
      ((zaddr)page_ptr + page_size) > (address + range_size)) {
    page->size = (address + range_size) - (zaddr)page_ptr;
    page->used_size = 0;
    page->curr_pos = page_ptr;
  } else if ((zaddr)page_ptr < address &&
             (zaddr)page_ptr < (address - range_size)) {
    page->size = page_size;
    page->used_size = (address - range_size) - (zaddr)page_ptr;
    page->curr_pos = (zpointer)(address - range_size);
  } else {
    page->size = page_size;
    page->used_size = 0;
    page->curr_pos = page_ptr;
  }
  page->isCodeCave = false;
  return page;
}

ZzMemoryPage *ZzNewNearCodeCave(zaddr address, zsize range_size,
                                zsize codeslice_size) {
  zsize page_size = ZzMemoryGetPageSzie();
  zpointer cave_ptr;
  zsize cave_size = codeslice_size;

  cave_ptr = ZzMemorySearchCodeCave(address, range_size, cave_size);

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

bool ZzAddMemoryPage(ZzAllocator *allocator, ZzMemoryPage *page) {
  if (!allocator)
    return false;
  if (allocator->size >= allocator->capacity) {
    ZzMemoryPage **pages =
        realloc(allocator->memory_pages,
                sizeof(ZzMemoryPage) * (allocator->capacity) * 2);
    if (!pages) {
      return false;
    }
    allocator->capacity = allocator->capacity * 2;
    allocator->memory_pages = pages;
  }
  allocator->memory_pages[allocator->size++] = page;
  ;
  return true;
}

//  1. try allocate from the history pages
//  2. try allocate a new page
//  3. add it to the page manager

// can just replace it with `ZzNewNearCodeSlice(0, 0, codeslice_size`
ZzCodeSlice *ZzNewCodeSlice(ZzAllocator *allocator, zsize codeslice_size) {
  ZzCodeSlice *codeslice;

  for (int i = 0; i < allocator->size; i++) {
    ZzMemoryPage *page = allocator->memory_pages[i];
    // 1. page is initialized
    // 2. can't be codecave
    // 3. the rest memory of this page is enough for codeslice_size
    // 4. the page address is near
    if (page->base && !page->isCodeCave &&
        (page->size - page->used_size) > codeslice_size) {
      codeslice = (ZzCodeSlice *)malloc(sizeof(ZzCodeSlice));
      codeslice->data = page->curr_pos;
      codeslice->size = codeslice_size;

      page->curr_pos += codeslice_size;
      page->used_size += codeslice_size;
      return codeslice;
    }
  }

  ZzMemoryPage *page;
  page = ZzNewMemoryPage();
  ZzAddMemoryPage(allocator, page);

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

ZzCodeSlice *ZzNewNearCodeSlice(ZzAllocator *allocator, zaddr address,
                                zsize range_size, zsize codeslice_size) {

  ZzCodeSlice *codeslice;

  for (int i = 0; i < allocator->size; i++) {
    ZzMemoryPage *page = allocator->memory_pages[i];
    // 1. page is initialized
    // 2. can't be codecave
    // 3. the rest memory of this page is enough for codeslice_size
    // 4. the page address is near
    if (page->base && !page->isCodeCave) {

      int flag = 0;
      zaddr split_addr = 0;

      if ((zaddr)page->curr_pos < address) {
        if (address - range_size < (zaddr)page->curr_pos) {
          // enough for codeslice_size
          if ((page->size - page->used_size) < codeslice_size)
            continue;
          flag = 1;

        } else if (address - range_size > (zaddr)page->curr_pos &&
                   (address - range_size) < ((zaddr)page->base + page->size)) {
          // enough for codeslice_size
          if (((zaddr)page->base + page->size) - (address - range_size) <
              codeslice_size)
            continue;
          split_addr = address - range_size;
          flag = 2;
        }
      } else {
        if (address + range_size > ((zaddr)page->base + page->size)) {
          // enough for codeslice_size
          if ((page->size - page->used_size) < codeslice_size)
            continue;
          flag = 1;
        } else if ((address + range_size) > (zaddr)page->curr_pos &&
                   (address + range_size) < ((zaddr)page->base + page->size)) {
          if ((address + range_size) - (zaddr)page->curr_pos > codeslice_size)
            continue;
          flag = 1;
        }
      }

      if (1 == flag) {
        codeslice = (ZzCodeSlice *)malloc(sizeof(ZzCodeSlice));
        codeslice->isCodeCave = page->isCodeCave;
        codeslice->data = page->curr_pos;
        codeslice->size = codeslice_size;

        page->curr_pos += codeslice_size;
        page->used_size += codeslice_size;
        return codeslice;
      } else if (2 == flag) {

        // new page
        ZzMemoryPage *new_page = (ZzMemoryPage *)malloc(sizeof(ZzMemoryPage));
        new_page->base = (zpointer)split_addr;
        new_page->size = ((zaddr)page->base + page->size) - split_addr;
        new_page->used_size = 0;
        new_page->curr_pos = (zpointer)split_addr;
        ZzAddMemoryPage(allocator, new_page);

        // origin page
        page->size = split_addr - (zaddr)page->base;

        codeslice = (ZzCodeSlice *)malloc(sizeof(ZzCodeSlice));
        codeslice->isCodeCave = false;
        codeslice->data = new_page->curr_pos;
        codeslice->size = codeslice_size;

        new_page->curr_pos += codeslice_size;
        new_page->used_size += codeslice_size;
        return codeslice;
      }
    }
  }

  ZzMemoryPage *page = NULL;
  page = ZzNewNearMemoryPage(address, range_size);
  // try allocate again, avoid the boundary page
  if (page && (page->size - page->used_size) < codeslice_size) {
    page = ZzNewNearMemoryPage(address, range_size);
  }
  if (!page) {
    page = ZzNewNearCodeCave(address, range_size, codeslice_size);
    if (!page)
      return NULL;
  }
  if (!page)
    return NULL;

  codeslice = (ZzCodeSlice *)malloc(sizeof(ZzCodeSlice));
  codeslice->isCodeCave = page->isCodeCave;
  codeslice->data = page->curr_pos;
  codeslice->size = codeslice_size;

  page->curr_pos += codeslice_size;
  page->used_size += codeslice_size;

  return codeslice;
}
