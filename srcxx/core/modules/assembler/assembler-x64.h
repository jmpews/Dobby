#ifndef CORE_MODULES_ASSEMBLER_X64_ASSEMBLER_H_
#define CORE_MODULES_ASSEMBLER_X64_ASSEMBLER_H_

#include "core/arch/arm/constants-arm.h"
#include "core/arch/arm/registers-arm.h"

#include "core/modules/assembler/assembler.h"

#include <assert.h>

namespace zz {
namespace x64 {

class PseudoLabel : public Label {
public:
};

class Operand {
public:
};

class MemOperand {
public:
};

class Assembler : public AssemblerBase {
public:
};

class TurboAssembler : public Assembler {
public:
};

} // namespace x64
} // namespace zz

#endif
