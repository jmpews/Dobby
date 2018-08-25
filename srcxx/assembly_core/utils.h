#ifndef ZZ_UTILS_H
#define ZZ_UTILS_H

#include "globals.h"

namespace zz {

namespace Utils {

static inline int32_t Low16Bits(int32_t value) {
  return static_cast<int32_t>(value & 0xffff);
}

static inline int32_t High16Bits(int32_t value) {
  return static_cast<int32_t>(value >> 16);
}

static inline int32_t Low32Bits(int64_t value) {
  return static_cast<int32_t>(value);
}

static inline int32_t High32Bits(int64_t value) {
  return static_cast<int32_t>(value >> 32);
}

} // namespace Utils
} // namespace zz

#endif