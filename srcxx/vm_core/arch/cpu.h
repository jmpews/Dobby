#ifndef ZZ_ARCH_CPU_H_
#define ZZ_ARCH_CPU_H_

#include "vm_core/globals.h"

class CPU {
public:
  static void FlushCache(uintptr_t address, uword size) {
  }
};

#endif
