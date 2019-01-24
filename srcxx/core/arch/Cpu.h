
#ifndef CORE_ARCH_CPU_H
#define CORE_ARCH_CPU_H

#include "CpuRegister.h"
#include "CpuFeature.h"

class CpuInfo {

public:
  CpuInfo();

public:
  // General features
  bool has_fpu() const {
    return has_fpu_;
  }
  int icache_line_size() const {
    return icache_line_size_;
  }
  int dcache_line_size() const {
    return dcache_line_size_;
  }
  static const int UNKNOWN_CACHE_LINE_SIZE = 0;

  // x86 features
  bool has_cmov() const {
    return has_cmov_;
  }
  bool has_sahf() const {
    return has_sahf_;
  }
  bool has_mmx() const {
    return has_mmx_;
  }
  bool has_sse() const {
    return has_sse_;
  }
  bool has_sse2() const {
    return has_sse2_;
  }
  bool has_sse3() const {
    return has_sse3_;
  }
  bool has_ssse3() const {
    return has_ssse3_;
  }
  bool has_sse41() const {
    return has_sse41_;
  }
  bool has_sse42() const {
    return has_sse42_;
  }
  bool has_osxsave() const {
    return has_osxsave_;
  }
  bool has_avx() const {
    return has_avx_;
  }
  bool has_fma3() const {
    return has_fma3_;
  }
  bool has_bmi1() const {
    return has_bmi1_;
  }
  bool has_bmi2() const {
    return has_bmi2_;
  }
  bool has_lzcnt() const {
    return has_lzcnt_;
  }
  bool has_popcnt() const {
    return has_popcnt_;
  }
  bool is_atom() const {
    return is_atom_;
  }

private:
  char vendor_[13];

  // General features
  int icache_line_size_;
  int dcache_line_size_;
  bool has_fpu_;

  // x86 features
  bool has_cmov_;
  bool has_sahf_;
  bool has_mmx_;
  bool has_sse_;
  bool has_sse2_;
  bool has_sse3_;
  bool has_ssse3_;
  bool has_sse41_;
  bool has_sse42_;
  bool has_osxsave_;
  bool has_avx_;
  bool has_fma3_;
  bool has_bmi1_;
  bool has_bmi2_;
  bool has_lzcnt_;
  bool has_popcnt_;
  bool is_atom_;
};

#endif
