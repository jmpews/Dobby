#include "dobby_internal.h"

#include "./NearMemoryArena.h"

#include "InterceptRouting/ExtraInternalPlugin/NearBranchTrampoline/PlatformUtil/GetProcessMemoryLayout.h"

#include <iostream>
#include <vector>

using namespace zz;

#define KB (1024uLL)
#define MB (1024uLL * KB)
#define GB (1024uLL * MB)

LiteMutableArray *NearMemoryArena::page_chunks = NULL;

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

int NearMemoryArena::PushMostNearCodePage(addr_t pos, int range) {
  std::vector<MemoryRegion> memory_layout = GetProcessMemoryLayout();
  int ndx                                 = get_region_index_within_layout(pos, memory_layout);
  if (!ndx) {
    FATAL_LOG("Get region index failed");
    return RT_FAILED;
  }

  addr_t blank_page = 0;
  // left <<<< search
  if (blank_page == 0) {
    addr_t blank_page_max = pos + range;
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
    addr_t blank_page_min = pos - range;
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
  newPage->chunks    = new LiteMutableArray(8);
  NearMemoryArena::page_chunks->pushObject(reinterpret_cast<LiteObject *>(newPage));
  return RT_SUCCESS;
}
#endif

int NearMemoryArena::PushMostNearPage(addr_t pos, size_t range, MemoryPermission permission) {
  addr_t min_page_addr, max_page_addr;
  min_page_addr       = ALIGN((pos - range), OSMemory::PageSize()) + OSMemory::PageSize();
  max_page_addr       = ALIGN((pos + range), OSMemory::PageSize()) - OSMemory::PageSize();
  addr_t nearPageAddr = 0;
  for (addr_t assumePageAddr = min_page_addr; assumePageAddr < max_page_addr; assumePageAddr += OSMemory::PageSize()) {
    nearPageAddr = (addr_t)OSMemory::Allocate((void *)assumePageAddr, OSMemory::PageSize(), permission);
    if (nearPageAddr)
      break;
  }

  if (nearPageAddr == 0) {
    LOG("Failed to alloc near page");
    return RT_FAILED;
  }

  PageChunk *newPage    = new PageChunk;
  newPage->page.address = (void *)nearPageAddr;
  newPage->page.length  = nearPageAddr;
  newPage->page_cursor  = nearPageAddr;
  newPage->permission   = permission;
  newPage->chunks       = new LiteMutableArray(8);
  NearMemoryArena::page_chunks->pushObject(reinterpret_cast<LiteObject *>(newPage));
  return RT_SUCCESS;
}

WritableDataChunk *NearMemoryArena::AllocateDataChunk(addr_t position, size_t range, int inSize) {
  return NearMemoryArena::AllocateChunk(position, range, inSize, kReadWrite);
}

AssemblyCodeChunk *NearMemoryArena::AllocateCodeChunk(addr_t position, size_t range, int inSize) {
  return NearMemoryArena::AllocateChunk(position, range, inSize, kReadWrite);
}

MemoryChunk *NearMemoryArena::AllocateChunk(addr_t position, size_t range, int inSize, MemoryPermission permission) {
  MemoryChunk *result = NULL;

  if (!NearMemoryArena::page_chunks) {
    NearMemoryArena::page_chunks = new LiteMutableArray;
  }

search_once_more:
  LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(NearMemoryArena::page_chunks);
  PageChunk *page              = NULL;
  while ((page = reinterpret_cast<PageChunk *>(iter->getNextObject())) != NULL) {
    if (page->permission == permission) {
      if (llabs((intptr_t)(page->page_cursor - position)) < range) {
        if ((page->page_cursor + inSize) < ((addr_t)page->page.address + page->page.length)) {
          break;
        }
      }
    }
  }
  delete iter;

  MemoryChunk *chunk = NULL;
  if (page) {
    chunk          = new MemoryChunk;
    chunk->address = (void *)page->page_cursor;
    chunk->length  = inSize;

    // update page cursor
    page->chunks->pushObject(reinterpret_cast<LiteObject *>(chunk));
    page->page_cursor += inSize;
    return chunk;
  }

  int rt = NearMemoryArena::PushMostNearPage(position, range, permission);
  if (rt == RT_SUCCESS) {
    goto search_once_more;
  }

  return NULL;
}
