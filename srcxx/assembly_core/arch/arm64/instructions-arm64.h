#ifndef ARCH_ARM64
#define ARCH_ARM64

#include "src/globals.h"

namespace zz {
namespace arm64 {

class Instruction {
public:
  enum { instruction_size = 4 };
  uint64_t pc;
  uint32_t bytes;
};

class InstructionStream {
public:
}

} // namespace arm64
} // namespace zz

#endif
