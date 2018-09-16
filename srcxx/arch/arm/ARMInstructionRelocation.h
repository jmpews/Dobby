#ifndef ZZZ_CXX_ARCH_ARM64_INSTRUCTION_RELOCATION
#define ZZZ_CXX_ARCH_ARM64_INSTRUCTION_RELOCATION

#include "srcxx/globals.h"
#include "vm_core/arch/arm/constants-arm.h"
#include "vm_core_extra/custom-code.h"

namespace zz {
namespace arm {

// Generate the relocated instruction
Code *GenRelocateCode(uintptr_t src_pc, int count);

} // namespace arm
} // namespace zz

#endif