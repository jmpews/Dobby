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

static addr_t search_near_blank_page(addr_t pos, size_t alloc_range) {
  addr_t min_page_addr, max_page_addr;
  min_page_addr = ALIGN((pos - alloc_range), OSMemory::PageSize()) + OSMemory::PageSize();
  max_page_addr = ALIGN((pos + alloc_range), OSMemory::PageSize()) - OSMemory::PageSize();

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
    // DLOG(0, "%p --- %p", region_start, region_end);
    if (region_end < max_page_addr) {
      if (region_start >= min_page_addr) {
        // sepcial-bank
        if (assumePageAddr == min_page_addr && i != 0) {
          MemoryRegion prev_region     = memory_layout[i - 1];
          addr_t       prev_region_end = (addr_t)prev_region.address + prev_region.length;
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

static addr_t search_near_blank_memory_chunk(addr_t pos, size_t alloc_range, int alloc_size) {
  addr_t min_page_addr, max_page_addr;
  min_page_addr = ALIGN((pos - alloc_range), OSMemory::PageSize()) + OSMemory::PageSize();
  max_page_addr = ALIGN((pos + alloc_range), OSMemory::PageSize()) - OSMemory::PageSize();

  std::vector<MemoryRegion> memory_layout = ProcessRuntimeUtility::GetProcessMemoryLayout();

  uint8_t *blank_chunk_addr = NULL;
  for (auto region : memory_layout) {
    // check if assume-page-addr in memory-layout
    if (region.permission == kReadExecute || region.permission == kRead) {
      if (((addr_t)region.address + region.length) <= max_page_addr) {
        if ((addr_t)region.address >= min_page_addr) {
#if defined(__APPLE__)
          if (*(uint32_t *)region.address == 0xfeedfacf)
            continue;
#endif
          char *blank_memory = (char *)malloc(alloc_size);
          memset(blank_memory, 0, alloc_size);
#if defined(__arm__) || defined(__aarch64__)
          alloc_size += (4 - 1);
          blank_chunk_addr = (uint8_t *)memmem(region.address, region.length, blank_memory, alloc_size);
          if (blank_chunk_addr) {
            int off = 4 - ((addr_t)blank_chunk_addr % 4);
            blank_chunk_addr += off;
          }
#else
          blank_chunk_addr = (uint8_t *)memmem(region.address, region.length, blank_memory, alloc_size);
#endif

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

WritableDataChunk *NearMemoryArena::AllocateDataChunk(addr_t position, size_t alloc_range, int alloc_size) {
  return NearMemoryArena::AllocateChunk(position, alloc_range, alloc_size, kReadWrite);
}

AssemblyCodeChunk *NearMemoryArena::AllocateCodeChunk(addr_t position, size_t alloc_range, int alloc_size) {
  return NearMemoryArena::AllocateChunk(position, alloc_range, alloc_size, kReadWrite);
}

MemoryChunk *NearMemoryArena::AllocateChunk(addr_t position, size_t alloc_range, int alloc_size,
                                            MemoryPermission permission) {
  MemoryChunk *result = NULL;

  if (!NearMemoryArena::page_chunks) {
    NearMemoryArena::page_chunks = new LiteMutableArray;
  }

search_once_more:
  LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(NearMemoryArena::page_chunks);
  PageChunk *             page = NULL;
  while ((page = reinterpret_cast<PageChunk *>(iter->getNextObject())) != NULL) {
    if (page->permission == permission) {
      if (llabs((intptr_t)(page->page_cursor - position)) < alloc_range) {
        if ((page->page_cursor + alloc_size) < ((addr_t)page->page.address + page->page.length)) {
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
    chunk->length  = alloc_size;

    // update page cursor
    page->chunks->pushObject(reinterpret_cast<LiteObject *>(chunk));
    page->page_cursor += alloc_size;
    return chunk;
  }

  addr_t blank_page_addr = 0;
  blank_page_addr        = search_near_blank_page(position, alloc_range);
  OSMemory::SetPermission((void *)blank_page_addr, OSMemory::PageSize(), permission);
  if (blank_page_addr) {
    NearMemoryArena::PushPage(blank_page_addr, permission);
    goto search_once_more;
  }

  addr_t blank_chunk_addr = 0;
  blank_chunk_addr        = search_near_blank_memory_chunk(position, alloc_range, alloc_size);
  if (blank_chunk_addr) {
    MemoryChunk *chunk = NULL;
    chunk              = new MemoryChunk;
    chunk->address     = (void *)blank_chunk_addr;
    chunk->length      = alloc_size;
    return chunk;
  }

  return NULL;
}
