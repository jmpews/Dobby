#pragma once

#include "MemoryAllocator/MemoryArena.h"

#include "core/assembler/assembler.h"

using namespace zz;

using AssemblyCode = MemRange;

class AssemblyCodeBuilder : MemZone {
public:
  static AssemblyCode *FinalizeFromTurboAssembler(AssemblerBase *assembler);
};
