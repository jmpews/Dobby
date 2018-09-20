#ifndef HOOKZZ_ARCH_ARM64_INSTRUCTION_RELOCATION
#define HOOKZZ_ARCH_ARM64_INSTRUCTION_RELOCATION

#include "srcxx/globals.h"
#include "vm_core/arch/arm/constants-arm.h"
#include "vm_core_extra/custom-code.h"

namespace zz {
namespace arm {

class CustomThumbPseudoLabel : public PseudoLabel {
public:
  enum CustomThumbPseudoLabelType { kThumb1Ldr };

  void link_confused_instructions(CodeBuffer *buffer = nullptr) {
    CodeBuffer *_buffer;
    if (buffer)
      _buffer = buffer;

    for (auto instruction : instructions_) {
      int32_t offset       = pos() - instruction.position_;
      const int32_t  inst = _buffer->Load<int32_t>(instruction.position_);
      const int16_t  inst1 = _buffer->Load<int16_t>(instruction.position_);
      const int16_t  inst2 = _buffer->Load<int16_t>(instruction.position_ + sizeof(int16_t));
      int32_t encoded      = 0;

      switch (instruction.type_) {
      case kThumb1Ldr: {
      } break;
      default:
        UNREACHABLE();
        break;
      }
    }
  };

};

class CustomThumbTurboAssembler : public TurboAssembler {
public:
  // =====
  void EmitInt16(int16_t val) {
    GetCodeBuffer()->Emit<int16_t>(val);
  }
  void Emit2Int16(int16_t val1, int16_t val2) {
    EmitInt16(val1);
    EmitInt16(val2);
  }
  // =====
  void t1_nop() {
    EmitInt16(0xbf00);
  }
  void t1_b(int32_t imm) {
    int32_t imm11 = bits(imm >> 1, 0, 10);
    EmitInt16(0xe000 | imm11);
  }
  // =====
  void T1_Ldr(Register r, CustomThumbPseudoLabel *label) {

  }
  // =====
  void t2_b(int32_t imm) {

  }
  void t2_bl(int32_t imm) {

  }
  void t2_ldr(Register r, MemOperand o) {

  }
  // =====
  void T2_Ldr(Register r, CustomThumbPseudoLabel *label) {

  }
};

// Generate the relocated instruction
Code *GenRelocateCode(uintptr_t src_pc, int count);

} // namespace arm
} // namespace zz

#endif