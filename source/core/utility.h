#ifndef CORE_UTILITY_H
#define CORE_UTILITY_H

namespace zz {

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

static inline bool CheckLength(word value, int len) {
  return true;
}
static inline bool CheckSignLength(word value, int len) {
  return true;
}
static inline bool CheckAlign(word value, int align) {
  return true;
}

} // namespace zz

#endif
