#ifndef ZZ_ARCHITECTURE_ARCH_ARM64_INSTRUCTIONS
#define ZZ_ARCHITECTURE_ARCH_ARM64_INSTRUCTIONS

#include "vm_core/architecture/macros-arch.h"

namespace zz {
namespace arm64 {

class Instruction {
public:
  enum { instruction_size = 4 };
  uint64_t pc;
  uint32_t bytes;
};

} // namespace arm64
} // namespace zz

#endif
