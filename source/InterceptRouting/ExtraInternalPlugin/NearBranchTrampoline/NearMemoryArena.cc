#include "./NearMemoryArena.h"

#include "dobby_internal.h"

#include "UserMode/PlatformUtil/ProcessRuntimeUtility.h"

#include <iostream>
#include <vector>

using namespace zz;

#define KB (1024uLL)
#define MB (1024uLL * KB)
#define GB (1024uLL * MB)

LiteMutableArray *NearMemoryArena::page_chunks = NULL;

#if 1

static addr_t search_near_blank_page(addr_t pos, int range) {
  addr_t min_page_addr, max_page_addr;
  min_page_addr = ALIGN((pos - range), OSMemory::PageSize()) + OSMemory::PageSize();
  max_page_addr = ALIGN((pos + range), OSMemory::PageSize()) - OSMemory::PageSize();

  std::vector<MemoryRegion> memory_layout = ProcessRuntimeUtility::GetProcessMemoryLayout();

  /*
   * min_page_addr/--special-blank--/==region==/--right-blank--/max_page_addr
   */

  addr_t nearPageAddr = 0, assumePageAddr = min_page_addr;

  for (int i = 0; i < memory_layout.size(); ++i) {
    MemoryRegion region = memory_layout[i];
    // check if assume-page-addr in memory-layout
    addr_t region_end   = (addr_t)region.address + region.length;
    addr_t region_start = (addr_t)region.address;
    if (region_end < max_page_addr) {
      if (region_start >= min_page_addr) {
        // sepcial-bank
        if (assumePageAddr == min_page_addr && i != 0) {
          MemoryRegion prev_region = memory_layout[i - 1];
          addr_t prev_region_end   = (addr_t)prev_region.address + prev_region.length;
          // check if have blank cave page
          if (region_start > prev_region_end) {
            assumePageAddr = min_page_addr > prev_region_end ? min_page_addr : prev_region_end;
            nearPageAddr   = (addr_t)OSMemory::Allocate((void *)assumePageAddr, OSMemory::PageSize(),
                                                      MemoryPermission::kReadExecute);
            if (nearPageAddr)
              break;
          }
        }

        // right-blank
        MemoryRegion next_region = memory_layout[i + 1];
        // check if have blank cave page
        if (region_end < (addr_t)next_region.address) {
          assumePageAddr = (addr_t)region.address + region.length;
          nearPageAddr =
              (addr_t)OSMemory::Allocate((void *)assumePageAddr, OSMemory::PageSize(), MemoryPermission::kReadExecute);
          if (nearPageAddr)
            break;
        }
      }
    }
  }
  return nearPageAddr;
}

static addr_t search_near_blank_memory_chunk(addr_t pos, int range, int in_size) {
  addr_t min_page_addr, max_page_addr;
  min_page_addr = ALIGN((pos - range), OSMemory::PageSize()) + OSMemory::PageSize();
  max_page_addr = ALIGN((pos + range), OSMemory::PageSize()) - OSMemory::PageSize();

  std::vector<MemoryRegion> memory_layout = ProcessRuntimeUtility::GetProcessMemoryLayout();

  uint8_t *blank_chunk_addr = NULL;
  for (auto region : memory_layout) {
    // check if assume-page-addr in memory-layout
    if (region.permission == kReadExecute || region.permission == kRead) {
      if (((addr_t)region.address + region.length) <= max_page_addr) {
        if ((addr_t)region.address >= min_page_addr) {
          char *blank_memory = (char *)malloc(in_size);
          memset(blank_memory, 0, in_size);
          blank_chunk_addr = (uint8_t *)memmem(region.address, region.length, blank_memory, in_size);
          if (blank_chunk_addr)
            break;
        }
      }
    }
  }
  return (addr_t)blank_chunk_addr;
}
#endif

int NearMemoryArena::PushPage(addr_t page_addr, MemoryPermission permission) {
  PageChunk *newPage    = new PageChunk;
  newPage->page.address = (void *)page_addr;
  newPage->page.length  = OSMemory::PageSize();
  newPage->page_cursor  = page_addr;
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

  addr_t blank_page_addr = 0;
  blank_page_addr        = search_near_blank_page(position, range);
  if (blank_page_addr) {
    NearMemoryArena::PushPage(blank_page_addr, kReadWrite);
    goto search_once_more;
  }

  addr_t blank_chunk_addr = 0;
  blank_chunk_addr        = search_near_blank_memory_chunk(position, range, inSize);
  if (blank_chunk_addr) {
    MemoryChunk *chunk = NULL;
    chunk              = new MemoryChunk;
    chunk->address     = (void *)blank_chunk_addr;
    chunk->length      = inSize;
    return chunk;
  }

  return NULL;
}
