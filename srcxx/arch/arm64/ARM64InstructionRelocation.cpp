#include "srcxx/arch/arm64/ARM64InstructionRelocation.h"

#include "vm_core/arch/arm64/registers-arm64.h"
#include "vm_core/modules/assembler/assembler-arm64.h"

#include "srcxx/globals.h"

using namespace zz::arm64;

void InstructionRelocation(uint64_t src_pc, int count, uint64_t dest_pc) {
  uint32_t *current_inst_ptr = static_cast<uint32_t *>(src_pc);
  uint32_t inst32            = *current_inst_ptr;
  int t                      = 0;

  zz::arm64::Assembler *assembler_ = new Assembler();
  zz::arm64::TurboAssembler *turbo_assembler;
#define __ assembler_->
#define _ turbo_assembler->
  while (t < count) {
    if (inst32 & LoadRegLiteralMask == LoadRegLiteralFixed) {
      int rt           = bits(inst32, 0, 4);
      int imm19        = bits(inst32, 5, 23);
      uint64_t address = LFT(imm19, 19, 2) + src_pc;
      _ Mov(Register::X(rt), address);
    }
  }
  return;
}