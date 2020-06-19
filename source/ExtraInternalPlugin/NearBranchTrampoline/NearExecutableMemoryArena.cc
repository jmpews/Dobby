#include "dobby_internal.h"

#include "./NearExecutableMemoryArena.h"

#include "ExtraInternalPlugin/NearBranchTrampoline/PlatformUtil/GetProcessMemoryLayout.h"

#include <iostream>
#include <vector>

using namespace zz;

#define KB (1024uLL)
#define MB (1024uLL * KB)
#define GB (1024uLL * MB)

LiteMutableArray *NearExecutableMemoryArena::page_chunks = NULL;

#if 0
static int get_region_index_within_layout(addr_t pos, std::vector<MemoryRegion> &layout) {
  addr_t region_start, region_end;
  for (int i = 0; i < layout.size(); i++) {
    region_start = layout[i].address;
    region_end   = region_start + layout[i].length;
    if (region_start < pos && region_end > pos) {
      return i;
    }
  }
  return 0;
}

int NearExecutableMemoryArena::PushMostNearCodePage(addr_t pos, int range_size) {
  std::vector<MemoryRegion> memory_layout = GetProcessMemoryLayout();
  int ndx                                 = get_region_index_within_layout(pos, memory_layout);
  if (!ndx) {
    FATAL_LOG("Get region index failed");
    return RT_FAILED;
  }

  addr_t blank_page = 0;
  // left <<<< search
  if (blank_page == 0) {
    addr_t blank_page_max = pos + range_size;
    for (int i = ndx; i > 0; i--) {
      // make sure blank region in required range.
      if (memory_layout[i].address + memory_layout[i].length > blank_page_max)
        break;
      if (memory_layout[i - 1].address > memory_layout[i].address + memory_layout[i].length) {
        blank_page = memory_layout[i].address + memory_layout[i].length;
        break;
      }
    }
  }

  // right >>>> search
  if (blank_page == 0) {
    addr_t blank_page_min = pos - range_size;
    for (int i = ndx; i < memory_layout.size(); i++) {
      // make sure blank region in required range.
      if (memory_layout[i].address - OSMemory::PageSize() < blank_page_min)
        break;
      if (memory_layout[i + 1].address + memory_layout[i + 1].length < memory_layout[i].address) {
        blank_page = memory_layout[i].address - OSMemory::PageSize();
        break;
      }
    }
  }

  if (blank_page == 0) {
    LOG("Failed to alloc near page");
    return RT_FAILED;
  }

  void *page_address = OSMemory::Allocate((void *)blank_page, OSMemory::PageSize(), MemoryPermission::kReadExecute);
  if (!page_address) {
    FATAL_LOG("Failed alloc executable page");
  }
  ExecutablePage *newPage = new ExecutablePage;
  newPage->address        = page_address;
  newPage->cursor         = newPage->address;
  newPage->capacity       = OSMemory::PageSize();
  newPage->code_chunks    = new LiteMutableArray(8);
  NearExecutableMemoryArena::page_chunks->pushObject(reinterpret_cast<LiteObject *>(newPage));
  return RT_SUCCESS;
}
#endif

int NearExecutableMemoryArena::PushMostNearCodePage(addr_t pos, int range_size) {
  void *near_page = NULL;
  addr_t min_page_addr, max_page_addr;
  min_page_addr = ALIGN((pos - range_size), OSMemory::PageSize()) + OSMemory::PageSize();
  max_page_addr = ALIGN((pos + range_size), OSMemory::PageSize()) - OSMemory::PageSize();
  for (addr_t page_addr = min_page_addr; page_addr < max_page_addr; page_addr += OSMemory::PageSize()) {
    near_page = OSMemory::Allocate((void *)page_addr, OSMemory::PageSize(), MemoryPermission::kReadExecute);
    if (near_page)
      break;
  }

  if (near_page == NULL) {
    LOG("Failed to alloc near page");
    return RT_FAILED;
  }

  ExecutablePage *newPage = new ExecutablePage;
  newPage->address        = near_page;
  newPage->cursor         = newPage->address;
  newPage->capacity       = OSMemory::PageSize();
  newPage->code_chunks    = new LiteMutableArray(8);
  NearExecutableMemoryArena::page_chunks->pushObject(reinterpret_cast<LiteObject *>(newPage));
  return RT_SUCCESS;
}

AssemblyCodeChunk *NearExecutableMemoryArena::AllocateCodeChunk(int inSize, addr_t pos, size_t range_size) {
  void *result                 = NULL;
  ExecutablePage *found_page   = NULL;
  AssemblyCodeChunk *codeChunk = NULL;

  if (!NearExecutableMemoryArena::page_chunks) {
    NearExecutableMemoryArena::page_chunks = new LiteMutableArray;
  }

search_once_more:
  LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(NearExecutableMemoryArena::page_chunks);
  ExecutablePage *_page        = 0;
  while ((_page = reinterpret_cast<ExecutablePage *>(iter->getNextObject())) != NULL) {
    if (llabs((intptr_t)((addr_t)_page->cursor - pos)) < range_size) {
      if (((addr_t)_page->cursor + inSize) < ((addr_t)_page->address + _page->capacity)) {
        found_page = _page;
        break;
      }
    }
  }
  delete iter;

  if (found_page) {
    codeChunk          = new AssemblyCodeChunk;
    codeChunk->address = found_page->cursor;
    codeChunk->size    = inSize;

    found_page->code_chunks->pushObject(reinterpret_cast<LiteObject *>(codeChunk));
    found_page->cursor = (void *)((addr_t)found_page->cursor + inSize);
    return codeChunk;
  }

  int rt = NearExecutableMemoryArena::PushMostNearCodePage(pos, range_size);
  if (rt == RT_SUCCESS) {
    goto search_once_more;
  }

  return NULL;
}
