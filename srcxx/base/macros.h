#ifndef V8_BASE_MACROS_H_
#define V8_BASE_MACROS_H_

#include "srcxx/base/logging.h"

inline void *AlignedAddress(void *address, size_t alignment) {
  // The alignment must be a power of two.
  DCHECK_EQ(alignment & (alignment - 1), 0u);
  return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(address) & ~static_cast<uintptr_t>(alignment - 1));
}

#endif