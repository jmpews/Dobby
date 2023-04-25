#pragma once

#include "dobby/common.h"
#include "MemoryAllocator.h"
#include "PlatformUtil/ProcessRuntimeUtility.h"

#define KB (1024uLL)
#define MB (1024uLL * KB)
#define GB (1024uLL * MB)

// memmem impl
inline void *memmem_impl(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
  if (!haystack || !needle) {
    return (void *)haystack;
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
    return l ? nullptr : (void *)r;
  }
}

struct NearMemoryAllocator {
  inline static NearMemoryAllocator *Shared();

  MemBlock allocNearCodeBlock(uint32_t in_size, addr_t pos, size_t range) {
    auto search_range = MemRange(pos - range, range * 2);
    return allocNearCodeBlock(in_size, search_range);
  }

  MemBlock allocNearCodeBlock(uint32_t in_size, MemRange search_range) {
    auto regions = ProcessRuntimeUtility::GetProcessMemoryLayout();

    // search from unused gap between regions
    for (int i = 0; i < regions.size(); ++i) {
      auto *region = &regions[i];
      auto *prev_region = i > 0 ? &regions[i - 1] : nullptr;
      auto *next_region = i < regions.size() - 1 ? &regions[i + 1] : nullptr;
      if (!next_region)
        break;

      auto unused_region_start = region->end();
      auto unused_region_size = next_region->start - region->end();
      MemRegion unused_region(unused_region_start, unused_region_size, kNoAccess);
      auto intersect = search_range.intersect(unused_region);
      if (intersect.size < in_size)
        continue;

      auto unused_page = (void *)ALIGN_FLOOR(intersect.start, OSMemory::PageSize());
      if (OSMemory::Allocate(OSMemory::PageSize(), kReadExecute, unused_page) != unused_page) {
        ERROR_LOG("allocate unused page failed");
        continue;
      }

      return MemBlock(intersect.start, (size_t)in_size);
    }

    // search unused code gap in region
    const uint8_t invalid_code_seq[0x1000] = {0};
    for (int i = 0; i < regions.size(); ++i) {
      auto *region = &regions[i];
      if (!(region->perm & MEM_PERM_X))
        continue;

      auto unused_code_gap = memmem_impl((void *)region->start, region->size, invalid_code_seq, in_size);
      if (!unused_code_gap)
        continue;
      return MemBlock((addr_t)unused_code_gap, (size_t)in_size);
    }

    return {};
  }
};

inline static NearMemoryAllocator gNearMemoryAllocator;
NearMemoryAllocator *NearMemoryAllocator::Shared() {
  return &gNearMemoryAllocator;
}