#include "./NearMemoryArena.h"

#include "dobby_internal.h"

#include "UserMode/PlatformUtil/ProcessRuntimeUtility.h"

using namespace zz;

#define KB (1024uLL)
#define MB (1024uLL * KB)
#define GB (1024uLL * MB)

std::vector<PageChunk> NearMemoryArena::page_chunks;

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

#if 1
static addr_t search_near_blank_page(addr_t pos, size_t alloc_range) {
  addr_t min_page_addr, max_page_addr;
  min_page_addr = next_page(addr_sub(pos, alloc_range), OSMemory::AllocPageSize());
  max_page_addr = prev_page(addr_add(pos, alloc_range), OSMemory::AllocPageSize());

  // region.start sorted
  std::vector<MemoryRegion> process_memory_layout = ProcessRuntimeUtility::GetProcessMemoryLayout();

  /*
   * min_page_addr/--special-blank--/==region==/--right-blank--/max_page_addr
   */

  addr_t resultPageAddr = 0, assume_page_addr = min_page_addr;

  // check first region
  addr_t first_region_start = (addr_t)process_memory_layout[0].address;
  if (min_page_addr < first_region_start) {
    resultPageAddr = prev_page(first_region_start, OSMemory::AllocPageSize());
    resultPageAddr =
        (addr_t)OSMemory::Allocate((void *)assume_page_addr, OSMemory::AllocPageSize(), MemoryPermission::kReadExecute);
    if (resultPageAddr)
      return resultPageAddr;
  }

  // check last region
  MemoryRegion last_region = process_memory_layout[process_memory_layout.size() - 1];
  addr_t last_region_end = (addr_t)last_region.address + last_region.length;
  if (max_page_addr < last_region_end) {
    resultPageAddr = next_page(last_region_end, OSMemory::AllocPageSize());
    resultPageAddr =
        (addr_t)OSMemory::Allocate((void *)assume_page_addr, OSMemory::AllocPageSize(), MemoryPermission::kReadExecute);
    if (resultPageAddr)
      return resultPageAddr;
  }

  for (int i = 0; i < process_memory_layout.size(); ++i) {
    MemoryRegion region = process_memory_layout[i];
    // check if assume-page-addr in memory-layout
    addr_t region_end = (addr_t)region.address + region.length;
    addr_t region_start = (addr_t)region.address;

    if (region_end < max_page_addr) {
      if (region_start >= min_page_addr) {

        // find the region locate in the [min_page_addr, max_page_addr]
        if (i >= 1 && assume_page_addr == min_page_addr) {
          MemoryRegion prev_region;
          prev_region = process_memory_layout[i - 1];
          addr_t prev_region_end =
              next_page((addr_t)prev_region.address + prev_region.length, OSMemory::AllocPageSize());
          // check if have blank cave page
          if (region_start > prev_region_end) {
            assume_page_addr = addr_max(min_page_addr, prev_region_end);
            resultPageAddr = (addr_t)OSMemory::Allocate((void *)assume_page_addr, OSMemory::AllocPageSize(),
                                                        MemoryPermission::kReadExecute);
            if (resultPageAddr)
              break;
          }
        }

        if (i <= process_memory_layout.size() - 2) {
          // right-blank
          MemoryRegion next_region = process_memory_layout[i + 1];
          // check if have blank cave page
          if (region_end < (addr_t)next_region.address) {
            assume_page_addr = next_page((addr_t)region.address + region.length, OSMemory::AllocPageSize());
            resultPageAddr = (addr_t)OSMemory::Allocate((void *)assume_page_addr, OSMemory::AllocPageSize(),
                                                        MemoryPermission::kReadExecute);
            if (resultPageAddr)
              break;
          }
        }
      }
    }
  }
  return resultPageAddr;
}

NearMemoryArena::NearMemoryArena() {
}

static addr_t search_near_blank_memory_chunk(addr_t pos, size_t alloc_range, int alloc_size) {
  addr_t min_page_addr, max_page_addr;
  min_page_addr = next_page(addr_sub(pos, alloc_range), OSMemory::AllocPageSize());
  max_page_addr = prev_page(addr_add(pos, alloc_range), OSMemory::AllocPageSize());

  std::vector<MemoryRegion> process_memory_layout = ProcessRuntimeUtility::GetProcessMemoryLayout();

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

#define NEAR_PAGE_ARRAYLEN 8

int NearMemoryArena::PushPage(addr_t page_addr, MemoryPermission permission) {
  PageChunk alloc_page;
  alloc_page.mem.address = (void *)page_addr;
  alloc_page.mem.length = OSMemory::PageSize();
  alloc_page.cursor = page_addr;
  alloc_page.permission = permission;
  NearMemoryArena::page_chunks.push_back(alloc_page);
  return RT_SUCCESS;
}

WritableDataChunk *NearMemoryArena::AllocateDataChunk(addr_t position, size_t alloc_range, int alloc_size) {
  return NearMemoryArena::AllocateChunk(position, alloc_range, alloc_size, kReadWrite);
}

AssemblyCodeChunk *NearMemoryArena::AllocateCodeChunk(addr_t position, size_t alloc_range, int alloc_size) {
  return NearMemoryArena::AllocateChunk(position, alloc_range, alloc_size, kReadExecute);
}

MemoryChunk *NearMemoryArena::AllocateChunk(addr_t position, size_t alloc_range, int alloc_size,
                                            MemoryPermission permission) {
  MemoryChunk *result = nullptr;

  PageChunk *found_page = nullptr;
try_alloc_page_again:
  for (auto &page : page_chunks) {
    if (page.permission == permission) {
      if ((page.cursor + alloc_size) < ((addr_t)page.mem.address + page.mem.length)) {
        found_page = &page;
        break;
      }
    }
  }

  if (found_page) {
    result = new MemoryChunk;
    result->address = (void *)found_page->cursor;
    result->length = alloc_size;

    // update page cursor
    found_page->chunks.push_back(result);
    found_page->cursor += alloc_size;
  }

  addr_t blank_page_addr = 0;
  blank_page_addr = search_near_blank_page(position, alloc_range);
  if (blank_page_addr) {
    OSMemory::SetPermission((void *)blank_page_addr, OSMemory::PageSize(), permission);
    NearMemoryArena::PushPage(blank_page_addr, permission);
    goto try_alloc_page_again;
  }

  if (permission == kReadWrite) {
    return nullptr;
  }

  addr_t blank_chunk_addr = 0;
  blank_chunk_addr = search_near_blank_memory_chunk(position, alloc_range, alloc_size);
  if (blank_chunk_addr) {
    result = new MemoryChunk;
    result->address = (void *)blank_chunk_addr;
    result->length = alloc_size;
    return result;
  }

  return nullptr;
}
