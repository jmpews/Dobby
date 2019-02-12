#include "globals.h"

#include "InstructionRelocation/arm64/ARM64InstructionRelocation.h"

#include "core/arch/arm64/registers-arm64.h"
#include "core/modules/assembler/assembler-arm64.h"
#include "core/modules/codegen/codegen-arm64.h"

// Compare and branch.
enum CompareBranchOp {
  CompareBranchFixed     = 0x34000000,
  CompareBranchFixedMask = 0x7E000000,
  CompareBranchMask      = 0xFF000000,
};

// Conditional branch.
enum ConditionalBranchOp {
  ConditionalBranchFixed     = 0x54000000,
  ConditionalBranchFixedMask = 0xFE000000,
  ConditionalBranchMask      = 0xFF000010,
};

namespace zz {
namespace arm64 {

typedef struct _PseudoLabelData {
  PseudoLabel label;
  uintptr_t address;
} PseudoLabelData;

AssemblyCode *GenRelocateCode(uint64_t src_address, int *relocate_size) {
  uint64_t src_pc = src_address;
  uint64_t cur_pc = src_pc;
  uint32_t inst   = *(uint32_t *)src_pc;

  // std::vector<PseudoLabelData> labels;
  LiteMutableArray *labels;

  TurboAssembler turbo_assembler_;
#define _ turbo_assembler_.
  while (cur_pc < (src_pc + *relocate_size)) {
    if ((inst & LoadRegLiteralFixedMask) == LoadRegLiteralFixed) {
      int rt                  = bits(inst, 0, 4);
      int32_t imm19           = bits(inst, 5, 23);
      uint64_t target_address = LFT(imm19, 19, 2) + cur_pc;

      _ Mov(X(rt), target_address);
      _ br(X(rt));
    } else if ((inst & CompareBranchFixedMask) == CompareBranchFixed) {
      // [cbz, cbnz] instruction fix scheme
      // cbz|cbnz #8
      // b #FalseLabel
      // ldr x17, =TargetAddressLabel
      // br x17
      // TargetAddressLabel:
      // .long target_address_lowbits
      // .long target_address_highbits
      // FalseLabel:
      // xxx
      // ===
      int rt;
      int32_t imm19;
      uint64_t target_address;
      imm19               = bits(inst, 5, 24);
      target_address      = (imm19 << 2) + cur_pc;
      int32_t cbz_or_cbnz = (inst & 0xff00001f) | (8 >> 2);
      // ===
      PseudoLabelData targetAddressLabel;
      targetAddressLabel.address = target_address;
      Label FalseLabel;
      _ Emit(cbz_or_cbnz);
      _ b(&FalseLabel);
      _ Ldr(x17, &targetAddressLabel.label);
      _ br(x17);
      _ bind(&FalseLabel);
      // ===
      // Record the pseudo label to realized at the last.
      labels->pushObject((LiteObject *)&targetAddressLabel);
    } else if ((inst & UnconditionalBranchFixedMask) == UnconditionalBranchFixed) {
      int32_t imm26;
      uint64_t target_address;
      imm26          = bits(inst, 0, 25);
      target_address = (imm26 << 2) + cur_pc;

      PseudoLabelData targetAddressLabel;
      targetAddressLabel.address = target_address;
      // ===
      _ Ldr(x17, &targetAddressLabel.label);
      if ((inst & UnconditionalBranchMask) == BL) {
        _ blr(x17);
      } else {
        _ br(x17);
      }
      // ===
      // Record the pseudo label to realized at the last.
      labels->pushObject((LiteObject *)&targetAddressLabel);
    } else if ((inst & ConditionalBranchFixedMask) == ConditionalBranchFixed) {
      int32_t imm19;
      uint64_t target_address;
      imm19          = bits(inst, 5, 23);
      target_address = (imm19 << 2) + cur_pc;
      int32_t b_cond = (inst & 0xff00001f) | LFT((8 >> 2), 19, 5);

      PseudoLabelData targetAddressLabel;
      targetAddressLabel.address = target_address;
      Label FalseLabel;
      // ===
      _ Emit(b_cond);
      _ b(&FalseLabel);
      _ Ldr(x17, &targetAddressLabel.label);
      _ br(x17);
      _ bind(&FalseLabel);
      // Record the pseudo label to realized at the last.
      labels->pushObject((LiteObject *)&targetAddressLabel);
    } else {
      // origin write the instruction bytes
      _ Emit(inst);
    }

    // Move to next instruction
    cur_pc += 4;
    inst = *(uint32_t *)cur_pc;
  }

  // Branch to the rest of instructions
  CodeGen codegen(&turbo_assembler_);
  codegen.LiteralLdrBranch(cur_pc);

// Realize all the Pseudo-Label-Data
#if 0
  for (auto it : labels) {
    _ PseudoBind(&(it.label));
    _ EmitInt64(it.address);
  }
#endif
  // Realize all the Pseudo-Label-Data
  PseudoLabelData *it;
  LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(labels);
  while ((it = reinterpret_cast<PseudoLabelData *>(iter->getNextObject())) != NULL) {
    _ PseudoBind(&(it->label));
    _ EmitInt64(it->address);
  }

  // Generate executable code
  AssemblyCode *code = AssemblyCode::FinalizeFromTurboAssember(&turbo_assembler_);
  return code;
}

} // namespace arm64
} // namespace zz
