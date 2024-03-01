#pragma once

#include "common/linear_allocator.h"
#include "PlatformUnifiedInterface/platform.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

struct MemRange {
  addr_t start_;
  size_t size;

  MemRange() : start_(0), size(0) {
  }

  MemRange(addr_t start, size_t size) : start_(start), size(size) {
  }

  addr_t start() const {
    return start_;
  }

  addr_t addr() const {
    return start_;
  }

  addr_t end() const {
    return start_ + size;
  }

  void resize(size_t in_size) {
    size = in_size;
  }

  void reset(addr_t in_start, size_t in_size) {
    start_ = in_start;
    size = in_size;
  }

  MemRange intersect(const MemRange &other) const {
    auto start = max(this->addr(), other.addr());
    auto end = min(this->end(), other.end());
    if (start < end)
      return MemRange(start, end - start);
    else
      return MemRange{};
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
  stl::vector<simple_linear_allocator_t *> code_page_allocators;
  stl::vector<simple_linear_allocator_t *> data_page_allocators;

  inline static MemoryAllocator *Shared();

  MemBlock allocMemBlock(size_t in_size, bool is_exec = true) {
    if (in_size > OSMemory::PageSize()) {
      ERROR_LOG("alloc size too large: %d", in_size);
      return {};
    }

    uint8_t *result = nullptr;
    auto allocators = is_exec ? code_page_allocators : data_page_allocators;
    for (auto allocator : allocators) {
      result = (uint8_t *)allocator->alloc(in_size);
      if (result)
        break;
    }

    if (!result) {
      {
        auto page = OSMemory::Allocate(OSMemory::PageSize(), kNoAccess);
        OSMemory::SetPermission(page, OSMemory::PageSize(), is_exec ? kReadExecute : kReadWrite);
        auto page_allocator = new simple_linear_allocator_t((uint8_t *)page, OSMemory::PageSize());
        if (is_exec)
          code_page_allocators.push_back(page_allocator);
        else
          data_page_allocators.push_back(page_allocator);
      }
      auto allocator = is_exec ? code_page_allocators.back() : data_page_allocators.back();
      result = (uint8_t *)allocator->alloc(in_size);
    }
    return MemBlock((addr_t)result, in_size);
  }

  MemBlock allocExecBlock(size_t size) {
    return allocMemBlock(size, true);
  }

  MemBlock allocDataBlock(size_t size) {
    return allocMemBlock(size, false);
  }
};

inline static MemoryAllocator gMemoryAllocator;
MemoryAllocator *MemoryAllocator::Shared() {
  return &gMemoryAllocator;
}

#undef min
#undef max