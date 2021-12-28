#include "NearMemoryAllocator.h"

#include "dobby_internal.h"

#include "PlatformUtil/ProcessRuntimeUtility.h"

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

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))


NearMemoryAllocator  *NearMemoryAllocator::shared_allocator = nullptr;
NearMemoryAllocator *NearMemoryAllocator::SharedAllocator() {
  if (NearMemoryAllocator::shared_allocator == nullptr) {
    NearMemoryAllocator::shared_allocator = new NearMemoryAllocator();
  }
  return NearMemoryAllocator::shared_allocator;
}


MemBlock *NearMemoryAllocator::allocateNearBlockFromDefaultAllocator(uint32_t size, addr_t pos, size_t search_range,
                                                                     bool executable) {
  addr_t min_valid_addr, max_valid_addr;
  min_valid_addr = pos - search_range;
  min_valid_addr = pos + search_range;

  auto allocateFromDefaultArena = [&](MemoryArena *arena) -> addr_t {
    addr_t unused_mem_start = arena->cursor_addr;
    addr_t unused_mem_end = unused_mem_start + arena->size;

    if (unused_mem_end < min_valid_addr || unused_mem_start > max_valid_addr)
      return 0;

    unused_mem_start = max(unused_mem_start, min_valid_addr);
    unused_mem_end = min(unused_mem_end, max_valid_addr);

    if (unused_mem_end - unused_mem_start < size)
      return 0;

    return unused_mem_start;
  };

  MemBlock *block = nullptr;
  if (executable) {
    for (auto iter = default_allocator->code_arenas.begin(); iter != default_allocator->code_arenas.end(); iter++) {
      auto arena = *iter;
      addr_t unused_mem = 0;
      unused_mem = allocateFromDefaultArena(arena);
      if (unused_mem)
        continue;

      size_t block_size = unused_mem - arena->cursor_addr;
      // TODO: optimize mem block
      block = arena->allocMemBlock(block_size);
      return block;
    }
  } else {
    for (auto iter = default_allocator->data_arenas.begin(); iter != default_allocator->data_arenas.end(); iter++) {
      auto arena = *iter;
      addr_t unused_mem = 0;
      unused_mem = allocateFromDefaultArena(arena);
      if (unused_mem)
        continue;

      size_t block_size = unused_mem - arena->cursor_addr;
      // TODO: optimize mem block
      block = arena->allocMemBlock(block_size);
      return block;
    }
  }
  return block;
}

static addr_t allocFromUnusedRegion(size_t size, addr_t pos, size_t search_range) {
  addr_t min_valid_addr, max_valid_addr;
  min_valid_addr = pos - search_range;
  max_valid_addr = pos + search_range;

  auto check_region_has_free_space = [&](MemRegion region, MemRegion next_region) -> addr_t {
    addr_t unused_mem_start = region.start + region.size;
    addr_t unused_mem_end = next_region.start;

    if (unused_mem_end < min_valid_addr || unused_mem_start > max_valid_addr)
      return 0;

    unused_mem_start = max(unused_mem_start, min_valid_addr);
    unused_mem_end = min(unused_mem_end, max_valid_addr);

    if (unused_mem_end - unused_mem_start < size)
      return 0;

    return unused_mem_start;
  };

  auto regions = ProcessRuntimeUtility::GetProcessMemoryLayout();
  for (size_t i = 0; i + 1 < regions.size(); i++) {
    addr_t unused_mem = 0;
    unused_mem = check_region_has_free_space(regions[i], regions[i + 1]);
    if (unused_mem == 0)
      continue;
    return unused_mem;
  }
  return 0;
}

MemBlock *NearMemoryAllocator::allocateNearBlockFromUnusedRegion(uint32_t size, addr_t pos, size_t search_range,
                                                                 bool executable) {

  addr_t min_valid_addr, max_valid_addr;
  min_valid_addr = pos - search_range;
  max_valid_addr = pos + search_range;

  auto check_region_has_free_space = [&](MemRegion region, MemRegion next_region) -> addr_t {
    addr_t unused_mem_start = region.start + region.size;
    addr_t unused_mem_end = next_region.start;

    if (unused_mem_end < min_valid_addr || unused_mem_start > max_valid_addr)
      return 0;

    unused_mem_start = max(unused_mem_start, min_valid_addr);
    unused_mem_end = min(unused_mem_end, max_valid_addr);

    if (unused_mem_end - unused_mem_start < size)
      return 0;

    return unused_mem_start;
  };

  addr_t unused_mem = 0;
  auto regions = ProcessRuntimeUtility::GetProcessMemoryLayout();
  for (size_t i = 0; i + 1 < regions.size(); i++) {
    unused_mem = check_region_has_free_space(regions[i], regions[i + 1]);
    if (unused_mem == 0)
      continue;
    break;
  }

  if (!unused_mem)
    return nullptr;

  auto unused_arena_size = ALIGN_CEIL(size, OSMemory::PageSize());
  auto unused_arena_addr = (addr_t)ALIGN_FLOOR(unused_mem, unused_arena_size);
  if (OSMemory::Allocate(unused_arena_size, kNoAccess, (void *)unused_arena_addr) == nullptr) {
    ERROR_LOG("[near memory allocator] allocate fixed page failed %p", unused_arena_addr);
    return nullptr;
  }

  MemBlock *block = nullptr;
  MemoryArena *arena = nullptr;
  if (executable) {
    arena = new CodeMemoryArena(unused_arena_addr, unused_arena_size);
    default_allocator->code_arenas.push_back(arena);
  } else {
    arena = new DataMemoryArena(unused_arena_addr, unused_arena_size);
    default_allocator->data_arenas.push_back(arena);
  }

  // skip placeholder block
  auto placeholder_block_size = pos - arena->addr;
  arena->allocMemBlock(placeholder_block_size);

  block = arena->allocMemBlock(size);
  return block;
}

MemBlock *NearMemoryAllocator::allocateNearBlock(uint32_t size, addr_t pos, size_t search_range, bool executable) {
  MemBlock *result = nullptr;
  result = allocateNearBlockFromDefaultAllocator(size, pos, search_range, executable);
  if (!result) {
    result = allocateNearBlockFromUnusedRegion(size, pos, search_range, executable);
  }

  if (!result) {
    ERROR_LOG("[near memory allocator] allocate near block failed (%p, %p, %p)", size, pos, search_range);
  }
  return result;
}

uint8_t *NearMemoryAllocator::allocateNearExecMemory(uint32_t size, addr_t pos, size_t search_range) {
  auto block = allocateNearBlock(size, pos, search_range, true);
  if (!block)
    return nullptr;

  DLOG(0, "[near memory allocator] allocate exec memory at: , size: ", block->addr, block->size);
  return (uint8_t *)block->addr;
}

uint8_t *NearMemoryAllocator::allocateNearExecMemory(uint8_t *buffer, uint32_t buffer_size, addr_t pos, size_t search_range) {
  auto mem = allocateNearExecMemory(buffer_size, pos, search_range);
  auto ret = CodePatch(mem, buffer, buffer_size);
  CHECK_EQ(ret, kMemoryOperationSuccess);
  return mem;
}

uint8_t *NearMemoryAllocator::allocateNearDataMemory(uint32_t size, addr_t pos, size_t search_range) {
  auto block = allocateNearBlock(size, pos, search_range, false);
  if (!block)
    return nullptr;

  DLOG(0, "[near memory allocator] allocate data memory at: , size: ", block->addr, block->size);
  return (uint8_t *)block->addr;
}

uint8_t *NearMemoryAllocator::allocateNearDataMemory(uint8_t *buffer, uint32_t buffer_size, addr_t pos, size_t search_range) {
  auto mem = allocateNearExecMemory(buffer_size, pos, search_range);
  memcpy(mem, buffer, buffer_size);
  return mem;
}
