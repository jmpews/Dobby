
#include "srcxx/arch/arch64/ARM64InstructionRelocation.h"

void InstructionRelocation(uint64_t src_pc, int count, uint64_t dest_pc) {
  uint32_t *current_inst_ptr = src_pc;
  uint32_t inst32            = *current_inst_ptr;
  int t                      = 0;
  Assembler *assembler_;
  TurboAssembler *turbo_assembler;
#define __ assembler_->
#define _ turbo_assembler->
  while (t < count) {
    if (inst32 & LoadRegLiteralMask == LoadRegLiteralFixed) {
      int rt           = bits(inst32, 0, 4);
      int imm19        = bits(inst32, 5, 23);
      uint64_t address = LFT(imm19, 19, 2) + src_pc;
      _ mov(Register::)
    }
  }
  return;
}
}