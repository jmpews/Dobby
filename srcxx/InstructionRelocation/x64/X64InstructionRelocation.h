#ifndef ZZ_INSTRUCTION_RELOCATION_X64_
#define ZZ_INSTRUCTION_RELOCATION_X64_

#include "globals.h"

#include "ExecMemory/AssemblyCode.h"

#include "core/arch/x64/constants-x64.h"

namespace zz {
namespace x64 {

// Generate the relocated instruction
AssemblyCode *GenRelocateCode(uint64_t src_pc, int *relocate_size);

} // namespace x64
} // namespace zz

#endif