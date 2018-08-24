#include
void InstructionRelocation(uint64_t src_pc, int count, uint64_t dest_pc) {
  uint32_t *current_inst_ptr = src_pc;
  uint32_t inst32            = *current_inst_ptr;
  int t                      = 0;
  Assembler *assembler_;
#define __ Assembler_->
  while (t < count) {
    if (inst32 & LoadRegLiteralMask == LoadRegLiteralFixed) {
      __
    }
  }
  return;
}
}