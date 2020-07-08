#ifndef INSTRUCTION_RELOCATION_ARM64_H
#define INSTRUCTION_RELOCATION_ARM64_H

#include "dobby_internal.h"

#include "core/arch/arm64/constants-arm64.h"

namespace zz {
namespace arm64 {

// Generate the relocated instruction
void GenRelocateCode(void *buffer, AssemblyCode *origin, AssemblyCode *relocated);

} // namespace arm64
} // namespace zz

#endif
