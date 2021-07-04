#include "./NearMemoryArena.h"

#include "dobby_internal.h"

#include "UserMode/PlatformUtil/ProcessRuntimeUtility.h"

using namespace zz;

#define KB (1024uLL)
#define MB (1024uLL * KB)
#define GB (1024uLL * MB)

#if defined(WIN32)
static const void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
  if (!haystack || !needle) {
    return haystack;
  } else {
    const char *h = (const char *)haystack;
    const char *n = (const char *)needle;
    size_t l = needlelen;
    const char *r = h;
    while (l && (l <= haystacklen)) {
      if (*n++ != *h++) {
        r = h;
        n = (const char *)needle;
        l = needlelen;
      } else {
        --l;
      }
      --haystacklen;
    }
    return l ? nullptr : r;
  }
}
#endif

static addr_t addr_max(addr_t a, addr_t b) {
  return a > b ? a : b;
}

static addr_t addr_sub(addr_t a, addr_t b) {
  return a > a - b ? a - b : 0;
}

static addr_t addr_add(addr_t a, addr_t b) {
  return a < a + b ? a + b : (addr_t)-1;
}

static addr_t prev_page(addr_t cur, int pagesize) {
  addr_t aligned_addr = ALIGN(cur, pagesize);
  addr_t ret = aligned_addr - pagesize;
  return ret <= aligned_addr ? ret : aligned_addr;
}

static addr_t next_page(addr_t cur, int pagesize) {
  addr_t aligned_addr = ALIGN(cur, pagesize);
  addr_t ret = aligned_addr + pagesize;
  return ret >= aligned_addr ? ret : aligned_addr;
}

static addr_t search_near_unused_region(size_t alloc_size, addr_t pos, size_t alloc_range) {
  addr_t min_valid_addr, max_valid_addr;
  min_valid_addr = pos - alloc_range;
  max_valid_addr = pos + alloc_range;

  auto check_region_has_free_space = [&] (MemRegion region_, MemRegion next_region_) -> addr_t {
    MemRange region = region_.mem;
    MemRange next_region = next_region_.mem;

    addr_t unused_mem_start = (addr_t)region.begin + region.size;
    addr_t unused_mem_end = (addr_t)next_region.begin;

    if(unused_mem_end < min_valid_addr || unused_mem_start > max_valid_addr)
      return 0;

    unused_mem_start = max(unused_mem_start, min_valid_addr);
    unused_mem_end = min(unused_mem_end, max_valid_addr);

    if(unused_mem_end - unused_mem_start < alloc_size)
      return 0;

    return unused_mem_start;
  };

  auto regions = ProcessRuntimeUtility::GetProcessMemoryLayout();
  for (size_t i = 0; i + 1 < regions.size(); i++) {
    addr_t unused_mem_start = 0;
    unused_mem_start = check_region_has_free_space(regions[i], regions[i + 1]);
    if(unused_mem_start == 0)
      continue;
    return unused_mem_start;
  }
  return 0;
}

DataBlock * NearMemoryArena::allocNearDataBlock(addr_t pos, size_t alloc_range, size_t alloc_size) {
  addr_t min_valid_addr, max_valid_addr;
  min_valid_addr = pos - alloc_range;
  min_valid_addr = pos + alloc_range;

  auto check_chunk_has_free_space = [&] (MemChunk *chunk) -> addr_t {
    addr_t unused_mem_start = chunk->cursor_addr;
    addr_t unused_mem_end = unused_mem_start + chunk->size;

    if(unused_mem_end < min_valid_addr || unused_mem_start > max_valid_addr)
      return 0;

    unused_mem_start = max(unused_mem_start, min_valid_addr);
    unused_mem_end = min(unused_mem_end, max_valid_addr);

    if(unused_mem_end - unused_mem_start < alloc_size)
      return 0;

    return unused_mem_start;
  };

  MemBlock *block = nullptr;
  for (auto *chunk : chunks_) {
    addr_t unused_mem_start = 0;
    unused_mem_start = check_chunk_has_free_space(chunk);
    if(unused_mem_start == 0)
      continue;

    alloc_size += (unused_mem_start - chunk->cursor_addr);
    if(unused_mem_start - chunk->cursor_addr > 0) {
      chunk->allocBlock(unused_mem_start - chunk->cursor_addr);
    }
    block = chunk->allocBlock(alloc_size);
  }

  if(block) {
    return block;
  }

  addr_t unused_addr = search_near_unused_region(alloc_size, pos, alloc_range);
  addr_t unused_page_addr = (addr_t)ALIGN_FLOOR(unused_addr, OSMemory::PageSize());

  auto allocChunk = [&](void *pos, size_t new_alloc_size) -> MemChunk * {
    size_t chunk_size = ALIGN_CEIL(new_alloc_size, OSMemory::PageSize());
    addr_t chunk_addr = (addr_t)OSMemory::Allocate(chunk_size, kReadWrite, pos);

    MemChunk *chunk = new MemChunk{.addr = chunk_addr, .cursor_addr = chunk_addr, .size = chunk_size};
    chunks_.push_back(chunk);
    return chunk;
  };

  MemChunk *new_chunk = nullptr;
  new_chunk   = allocChunk((void *)unused_page_addr, alloc_size);

  // placeholder block
  if(unused_addr - unused_page_addr > 0) {
    new_chunk->allocBlock(unused_addr - unused_page_addr);
  }
  block = new_chunk->allocBlock(alloc_size);

  return block;
}

#if 0
static addr_t search_near_blank_memory_chunk(addr_t pos, size_t alloc_range, int alloc_size) {
  addr_t min_page_addr, max_page_addr;
  min_page_addr = next_page(addr_sub(pos, alloc_range), OSMemory::AllocPageSize());
  max_page_addr = prev_page(addr_add(pos, alloc_range), OSMemory::AllocPageSize());

  std::vector<MemRange> process_memory_layout = ProcessRuntimeUtility::GetProcessMemoryLayout();

  uint8_t *blank_chunk_addr = nullptr;
  for (auto region : process_memory_layout) {
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

//int NearMemoryArena::PushPage(addr_t page_addr, MemoryPermission permission) {
//  PageChunk *alloc_page = new PageChunk;
//  alloc_page->mem.address = (void *)page_addr;
//  alloc_page->mem.length = OSMemory::PageSize();
//  alloc_page->cursor = page_addr;
//  alloc_page->permission = permission;
//  NearMemoryArena::page_chunks.push_back(alloc_page);
//  return RT_SUCCESS;
//}
//
//WritableDataChunk *NearMemoryArena::AllocateDataChunk(addr_t position, size_t alloc_range, int alloc_size) {
//  return NearMemoryArena::AllocateChunk(position, alloc_range, alloc_size, kReadWrite);
//}
//
//AssemblyCode *NearMemoryArena::AllocateCodeChunk(addr_t position, size_t alloc_range, int alloc_size) {
//  return NearMemoryArena::AllocateChunk(position, alloc_range, alloc_size, kReadExecute);
//}
//
//MemoryChunk *NearMemoryArena::AllocateChunk(addr_t position, size_t alloc_range, int alloc_size,
//                                            MemoryPermission permission) {
//  MemoryChunk *result = nullptr;
//
//  PageChunk *found_page = nullptr;
//try_alloc_page_again:
//  for (auto *page : page_chunks) {
//    if (page->permission != permission) {
//      continue;
//    }
//    if ((page->cursor + alloc_size) < ((addr_t)page->mem.address + page->mem.length)) {
//      found_page = page;
//      break;
//    }
//  }
//
//  if (found_page) {
//    result = new MemoryChunk;
//    result->address = (void *)found_page->cursor;
//    result->length = alloc_size;
//
//    // update page cursor
//    found_page->chunks.push_back(result);
//    found_page->cursor += alloc_size;
//  }
//
//  addr_t blank_page_addr = 0;
//  blank_page_addr = search_near_blank_page(position, alloc_range);
//  if (blank_page_addr) {
//    OSMemory::SetPermission((void *)blank_page_addr, OSMemory::PageSize(), permission);
//    NearMemoryArena::PushPage(blank_page_addr, permission);
//    goto try_alloc_page_again;
//  }
//
//  if (permission == kReadWrite) {
//    return nullptr;
//  }
//
//  addr_t blank_chunk_addr = 0;
//  blank_chunk_addr = search_near_blank_memory_chunk(position, alloc_range, alloc_size);
//  if (blank_chunk_addr) {
//    result = new MemoryChunk;
//    result->address = (void *)blank_chunk_addr;
//    result->length = alloc_size;
//    return result;
//  }
//
//  return nullptr;
//}
