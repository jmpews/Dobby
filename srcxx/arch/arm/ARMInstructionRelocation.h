#ifndef HOOKZZ_ARCH_ARM64_INSTRUCTION_RELOCATION
#define HOOKZZ_ARCH_ARM64_INSTRUCTION_RELOCATION

#include "srcxx/globals.h"
#include "vm_core/arch/arm/constants-arm.h"
#include "vm_core_extra/custom-code.h"

namespace zz {
namespace arm {

// custom thumb pseudo label for thumb/thumb2
class CustomThumbPseudoLabel : public PseudoLabel {
public:
  // thumb1/thumb2 pseudo label type, only support Thumb1-Ldr | Thumb2-Ldr
  enum CustomThumbPseudoLabelType { kThumb1Ldr, kThumb2Ldr };

  // fix the instruction which not link to the label yet.
  void link_confused_instructions(CodeBuffer *buffer = nullptr) {
    CodeBuffer *_buffer;
    if (buffer)
      _buffer = buffer;

    for (auto instruction : instructions_) {
      // instruction offset to label
      int32_t offset      = pos() - instruction.position_;
      const int32_t inst  = _buffer->Load<int32_t>(instruction.position_);
      const int16_t inst1 = _buffer->Load<int16_t>(instruction.position_);
      const int16_t inst2 = _buffer->Load<int16_t>(instruction.position_ + sizeof(int16_t));
      int32_t encoded     = 0;

      switch (instruction.type_) {
      case kThumb1Ldr: {
        uint32_t imm8 = offset >> 2;
        CHECK(imm8 < (1 << 8));
        encoded = inst1 & 0xff00;
        encoded = encoded | imm8;
        _buffer->Store<int16_t>(instruction.position_, encoded);
      } break;
      case kThumb2Ldr: {
        uint32_t imm12 = offset;
        CHECK(imm12 < (1 << 12));
        encoded = inst & 0xfffff000;
        encoded = encoded | imm12;
        _buffer->Store<int32_t>(instruction.position_, encoded);
      }
      default:
        UNREACHABLE();
        break;
      }
    }
  }
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