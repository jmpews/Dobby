#ifndef INSTRUCTION_RELOCATION_X64_H
#define INSTRUCTION_RELOCATION_X64_H

#include "common/headers/common_header.h"

#include "core/arch/x64/constants-x64.h"

#include "MemoryAllocator/AssemblyCodeBuilder.h"

namespace zz {
namespace x64 {

// Generate the relocated instruction
AssemblyCodeChunk *GenRelocateCodeAndBranch(void *buffer, int *relocate_size, addr_t from_ip, addr_t to_ip);

} // namespace x64
} // namespace zz

#endif