#include "srcxx/arch/arm64/ARM64InstructionRelocation.h"

#include "vm_core/arch/arm64/registers-arm64.h"
#include "vm_core/modules/assembler/assembler-arm64.h"

#include "srcxx/globals.h"

using namespace zz;
using namespace zz::arm64;

// Compare and branch.
enum CompareBranchOp {
  CompareBranchFixed = 0x34000000,
  CompareBranchMask  = 0xFF000000,
};

// Conditional branch.
enum ConditionalBranchOp {
  ConditionalBranchFixed = 0x54000000,
  ConditionalBranchMask  = 0xFF000010,
};

void InstructionRelocation(uint64_t src_pc, int count, uint64_t dest_pc) {
  uint32_t *current_inst_ptr = (uint32_t *)src_pc;
  uint64_t cur_pc            = src_pc;
  uint32_t inst              = *current_inst_ptr;
  int t                      = 0;

  TurboAssembler turbo_assembler_;
#define _ turbo_assembler_.
  while (t < count) {
    if ((inst & LoadRegLiteralMask) == LoadRegLiteralFixed) {
      int rt                  = bits(inst, 0, 4);
      int32_t imm19           = bits(inst, 5, 23);
      uint64_t target_address = LFT(imm19, 19, 2) + cur_pc;

      _ Mov(Register::X(rt), target_address);
      _ br(X(rt));
    } else if ((inst & CompareBranchMask) == CompareBranchFixed) {
      // [cbz, cbnz] instruction fix scheme
      // cbz|cbnz #8
      // b #FalseLabel
      // ldr x17, =TargetAddress
      // br x17
      // TargetAddress:
      // .long target_address_lowbits
      // .long target_address_highbits
      // FalseLabel:
      // xxx

      // =====

      int rt;
      int32_t imm19;
      uint64_t target_address;
      imm19               = bits(inst, 5, 24);
      target_address      = (imm19 << 2) + cur_pc;
      int32_t cbz_or_cbnz = (inst & 0xff00001f) | (8 >> 2);

      // =====

      PseudoLabel TargetAddress;
      Label FalseLabel;
      _ Emit(cbz_or_cbnz);
      _ b(&FalseLabel);

      _ Ldr(x17, &TargetAddress);
      _ br(x17);
      _ PseudoBind(&TargetAddress);
      _ EmitInt64(target_address);

      _ bind(&FalseLabel);
    } else if ((inst & UnconditionalBranchMask) == UnconditionalBranchFixed) {
      int32_t imm26;
      uint64_t target_address;
      imm26          = bits(inst, 0, 25);
      target_address = (imm26 << 2) + cur_pc;

      // =====

      PseudoLabel TargetAddress;
      _ Ldr(x17, &TargetAddress);
      if ((inst & UnconditionalBranchMask) == BL) {
        _ blr(x17);
      } else {
        _ br(x17);
      }
      _ PseudoBind(&TargetAddress);
      _ EmitInt64(target_address);

    } else if ((inst & ConditionalBranchMask) == ConditionalBranchFixed) {
      UNIMPLEMENTED();
    } else {
      // origin write the instruction bytes
    }
  }
  return;
}
