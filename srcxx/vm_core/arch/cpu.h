#ifndef ZZ_ARCH_CPU_H_
#define ZZ_ARCH_CPU_H_

#include "vm_core/globals.h"

class CpuFeatures {
public:
  static void FlushICache(void *start, size_t size) {
    FlushICache(start, (void *)((uintptr_t)start + size));
  }

  static void FlushICache(void *startp, void *endp);

  static void ClearCache(void *startp, void *endp);
};

#endif
