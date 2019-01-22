#ifndef ZZ_INSTRUCTION_RELOCATION_ARM64_
#define ZZ_INSTRUCTION_RELOCATION_ARM64_

#include "globals.h"

#include "ExecMemory/AssemblyCode.h"

#include "core/arch/arm64/constants-arm64.h"

// PC relative addressing.
enum PCRelAddressingOp {
  PCRelAddressingFixed     = 0x10000000,
  PCRelAddressingFixedMask = 0x1F000000,
  PCRelAddressingMask      = 0x9F000000,

  ADR  = PCRelAddressingFixed | 0x00000000,
  ADRP = PCRelAddressingFixed | 0x80000000
};

namespace zz {
namespace arm64 {

// Generate the relocated instruction
AssemblyCode *GenRelocateCode(uint64_t src_pc, int *relocate_size);

} // namespace arm64
} // namespace zz

#endif