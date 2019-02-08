#ifndef CORE_ARCH_CPU_FEATURE_H_
#define CORE_ARCH_CPU_FEATURE_H_

#include "globals.h"

class CpuFeatures {
public:
  static void FlushICache(void *start, size_t size) {
    ClearCache(start, (void *)((uintptr_t)start + size));
  }

  static void FlushICache(void *start, void *end) {
    ClearCache(start, end);
  }

  static void ClearCache(void *start, void *end);
};

#endif
