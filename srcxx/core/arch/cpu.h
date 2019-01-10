#ifndef ARCH_CPU_H_
#define ARCH_CPU_H_

#include "vm_core/globals.h"

class CpuFeatures {
public:
  static void FlushICache(void *start, size_t size) { FlushICache(start, (void *)((uintptr_t)start + size)); }

  static void FlushICache(void *start, void *end);

  static void ClearCache(void *start, void *end);
};

#endif
