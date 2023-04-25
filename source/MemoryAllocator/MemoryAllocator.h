#pragma once

#include "common/linear_allocator.h"
#include "PlatformUnifiedInterface/platform.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

struct MemRange {
  addr_t start;
  size_t size;

  MemRange() : start(0), size(0) {
  }

  MemRange(addr_t start, size_t size) : start(start), size(size) {
  }

  addr_t addr() const {
    return start;
  }

  addr_t end() const {
    return start + size;
  }

  MemRange intersect(const MemRange &other) const {
    auto start = max(this->start, other.start);
    auto end = min(this->end(), other.end());
    if (start < end)
      return MemRange(start, end - start);
    else
      return MemRange(0, 0);
  }

  void resize(size_t in_size) {
    size = in_size;
  }

  void reset(addr_t in_start, size_t in_size) {
    start = in_start;
    size = in_size;
  }
};

struct MemBlock : MemRange {
  MemBlock() : MemRange() {
  }

  MemBlock(addr_t start, size_t size) : MemRange(start, size) {
  }
};

using CodeMemBlock = MemBlock;
using DataMemBlock = MemBlock;

struct MemoryAllocator {
  tinystl::vector<simple_linear_allocator_t> code_page_allocators;
  tinystl::vector<simple_linear_allocator_t> data_page_allocators;

public:
  inline static MemoryAllocator *Shared();

  MemBlock allocDataBlock(size_t in_size) {
    if (in_size > OSMemory::PageSize()) {
      ERROR_LOG("alloc size too large: %d", in_size);
      return {};
    }

    uint8_t *result = 0;
    for (auto &allocator : data_page_allocators) {
      result = (uint8_t *)allocator.alloc(in_size);
      if (result)
        break;
    }

    if (!result) {
      auto page = OSMemory::Allocate(OSMemory::PageSize(), kNoAccess);
      OSMemory::SetPermission(page, OSMemory::PageSize(), kReadWrite);
      auto page_allocator = simple_linear_allocator_t((uint8_t *)page, OSMemory::PageSize());
      data_page_allocators.push_back(page_allocator);
      result = (uint8_t *)data_page_allocators.back().alloc(in_size);
    }
    return MemBlock((addr_t)result, in_size);
  }

  MemBlock allocExecBlock(size_t size) {
    if (size > OSMemory::PageSize()) {
      ERROR_LOG("alloc size too large: %d", size);
      return {};
    }

    uint8_t *result = 0;
    for (auto &allocator : code_page_allocators) {
      result = (uint8_t *)allocator.alloc(size);
      if (result)
        break;
    }

    if (!result) {
      auto page = OSMemory::Allocate(OSMemory::PageSize(), kNoAccess);
      OSMemory::SetPermission(page, OSMemory::PageSize(), kReadExecute);
      auto page_allocator = simple_linear_allocator_t((uint8_t *)page, OSMemory::PageSize());
      code_page_allocators.push_back(page_allocator);
      result = (uint8_t *)code_page_allocators.back().alloc(size);
    }
    return MemBlock((addr_t)result, size);
  }
};

inline static MemoryAllocator gMemoryAllocator;
MemoryAllocator *MemoryAllocator::Shared() {
  return &gMemoryAllocator;
}