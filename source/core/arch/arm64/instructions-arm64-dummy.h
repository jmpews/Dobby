#ifndef CORE_ARCH_INSTRUCTION_ARM64_H
#define CORE_ARCH_INSTRUCTION_ARM64_H

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
