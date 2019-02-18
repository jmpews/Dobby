#include "core/modules/assembler/assembler-x64.h"

using namespace zz::x64;

void Assembler::jmp(Immediate imm) {
  buffer_->Emit8(0xE9);
  buffer_->Emit32((int)imm.value());
}

addr_t TurboAssembler::CurrentIP() {
  return pc_offset() + (addr_t)realized_address_;
}
