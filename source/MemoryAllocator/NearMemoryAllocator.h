#pragma once

#include "dobby/common.h"
#include "MemoryAllocator.h"
#include "PlatformUtil/ProcessRuntime.h"
#include <stdint.h>

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

inline dobby_alloc_near_code_callback_t custom_alloc_near_code_handler = nullptr;
PUBLIC inline void dobby_register_alloc_near_code_callback(dobby_alloc_near_code_callback_t handler) {
  features::apple::arm64e_pac_strip_and_sign(handler);
  custom_alloc_near_code_handler = handler;
}

struct NearMemoryAllocator {
  inline static NearMemoryAllocator *Shared();

  MemBlock allocNearCodeBlock(uint32_t in_size, addr_t pos, size_t range) {
    if (custom_alloc_near_code_handler) {
      auto near_code = custom_alloc_near_code_handler(in_size, pos, range);
      if (near_code)
        return MemBlock(near_code, in_size);
    } else {
      auto search_range = MemRange(pos - range, range * 2);
      return allocNearCodeBlock(in_size, search_range);
    }
    return {};
  }

  MemBlock allocNearCodeBlock(uint32_t in_size, MemRange search_range) {
    auto regions = ProcessRuntime::getMemoryLayout();

    // search from unused gap between regions
    for (int i = 0; i < regions.size(); ++i) {
      auto *region = &regions[i];
      auto *prev_region = i > 0 ? &regions[i - 1] : nullptr;
      auto *next_region = i < regions.size() - 1 ? &regions[i + 1] : nullptr;
      if (!next_region)
        break;

      auto unused_region_start = region->end();
      auto unused_region_size = next_region->addr() - region->end();
      MemRegion unused_region(unused_region_start, unused_region_size, kNoAccess);
      auto intersect = search_range.intersect(unused_region);
      if (intersect.size < in_size)
        continue;

      auto unused_page = (void *)ALIGN_FLOOR(intersect.addr(), OSMemory::PageSize());
      if (OSMemory::Allocate(OSMemory::PageSize(), kReadExecute, unused_page) != unused_page) {
        ERROR_LOG("allocate unused page failed");
        continue;
      }

      return MemBlock(intersect.addr(), (size_t)in_size);
    }

    // search unused code gap in region
    const uint8_t invalid_code_seq[0x1000] = {0};
    for (int i = 0; i < regions.size(); ++i) {
      auto *region = &regions[i];
      if (!(region->perm & MEM_PERM_X))
        continue;

      auto intersect = search_range.intersect(*region);
      if (intersect.size < in_size)
        continue;

      auto search_start = intersect.addr();
      auto search_size = intersect.size;

      auto alignmemt = 4;
      auto unused_code_gap =
          memmem_impl((void *)search_start, search_size, invalid_code_seq, in_size + (alignmemt - 1));
      if (!unused_code_gap)
        continue;
      unused_code_gap = (void *)ALIGN_CEIL(unused_code_gap, alignmemt);
      return MemBlock((addr_t)unused_code_gap, (size_t)in_size);
    }

    return {};
  }
};

inline static NearMemoryAllocator gNearMemoryAllocator;
NearMemoryAllocator *NearMemoryAllocator::Shared() {
  return &gNearMemoryAllocator;
}