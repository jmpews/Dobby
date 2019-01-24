#ifndef ARCH_X64_CPU_H_
#define ARCH_X64_CPU_H_

#include "core/arch/Cpu.h"


class X64CpuFeatures : public CpuFeatures {
public:
  static bool sse2_supported() {
    return CpuInfo().has_sse2();
  }
  static bool sse4_1_supported() {
    return CpuInfo().has_sse41();
  }
private:
  static bool sse2_supported_;
  static bool sse4_1_supported_;
};

#endif