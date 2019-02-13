#include "core/modules/assembler/assembler-arm.h"

namespace zz {
namespace arm {

Assembler::Assembler() {
}

void Assembler::EmitARMInst(arm_inst_t inst) {
  buffer_->EmitARMInst(inst);
}

void Assembler::EmitAddress(uint32_t value) {
  buffer_->Emit32(value);
}

} // namespace arm
} // namespace zz
