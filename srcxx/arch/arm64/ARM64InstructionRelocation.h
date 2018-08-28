#ifndef ZZZ_CXX_ARCH_ARM64_INSTRUCTION_RELOCATION
#define ZZZ_CXX_ARCH_ARM64_INSTRUCTION_RELOCATION

#include "vm_core/architecture/arch/arm64/constants-arm64.h"
#include "srcxx/globals.h"

// PC relative addressing.
enum PCRelAddressingOp {
  PCRelAddressingFixed = 0x10000000,
  PCRelAddressingFMask = 0x1F000000,
  PCRelAddressingMask  = 0x9F000000,
  ADR                  = PCRelAddressingFixed | 0x00000000,
  ADRP                 = PCRelAddressingFixed | 0x80000000
};

namespace zz {
namespace arm64 {
void InstructionRelocation(uint64_t src_pc, int count, uint64_t dest_pc) {
}

} // namespace arm64
} // namespace zz

#endif