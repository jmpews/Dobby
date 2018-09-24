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

class CustomThumbAssembler : public Assembler {
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
    ZAssert(CheckSignLength(imm, 12));
    ZAssert(CheckAlign(imm, 2));

    int32_t imm11 = bits(imm >> 1, 0, 10);
    EmitInt16(0xe000 | imm11);
  }

  // =====
  void t2_b(uint32_t imm) {
    EmitThumb2Branch(AL, imm, false);
  }
  void t2_bl(uint32_t imm) {
    EmitThumb2Branch(AL, imm, true);
  }
  void t2_blx(uint32_t imm) {
    UNIMPLEMENTED();
  }

  // =====
  void t2_ldr(Register dst, const MemOperand &src) {
    EmitThumb2LoadStore(true, dst, src);
  }

private:
  void EmitThumb2LoadLiteral() {
  }
  void EmitThumb2LoadStore(bool load, Register rt, const MemOperand x) {
    bool index, add, wback;
    if (x.IsRegisterOffset()) {
      if (x.offset() > 0) {
        index = true, add = true, wback = false;
        uint32_t imm12 = x.offset();
        Emit(0xf8c00000 | LFT(rt.code(), 4, 12) | x.offset());
      }
    } else {
      // use bit accelerate
      uint32_t P, W, U;
      uint32_t imm8 = x.offset() > 0 ? x.offset() : -x.offset();
      U             = x.offset() > 0 ? 0 : B9;
      if (x.IsPostIndex()) {
        P = 0, W = B8;
      } else if (x.IsPreIndex()) {
        P = B10, W = B8;
      }
      index = (P == B10);
      add   = (U == B9);
      wback = (W == B8);
      Emit(0xf8400800 | P | U | W | imm8);
    }
  }

  // =====
  void EmitThumb2Branch(Condition cond, uint32_t operand, bool link) {
    ZAssert(CheckSignLength(operand, 25));
    ZAssert(CheckAlign(operand, 2));

    uint32_t encoding;
    uint32_t value;
    uint32_t signbit = (operand >> 31) & 0x1;
    uint32_t i1      = (operand >> 22) & 0x1;
    uint32_t i2      = (operand >> 21) & 0x1;
    uint32_t imm10   = (operand >> 11) & 0x03ff;
    uint32_t imm11   = operand & 0x07ff;
    uint32_t j1      = (i1 ^ signbit) ? 0 : 1;
    uint32_t j2      = (i2 ^ signbit) ? 0 : 1;
    value            = (signbit << 26) | (j1 << 13) | (j2 << 11) | (imm10 << 16) | imm11;

    if (cond != AL) {
      UNIMPLEMENTED();
    }
    encoding = 0xf0009000;
    if (link) {
      // Not use LFT(1, 1, 14), and use B14 for accelerate
      encoding = encoding | B14;
    }
    encoding |= value;
    Emit(encoding);
  }
};

class CustomThumbTurboAssembler : public CustomThumbAssembler {
public:
  // =====
  void T1_Ldr(Register rt, CustomThumbPseudoLabel *label) {
    if (label->is_bound()) {
      const int64_t dest = label->pos() - buffer_.Size();
      ldr(rt, MemOperand(pc, dest));
    } else {
      // record this ldr, and fix later.
      label->link_to(buffer_.Size(), CustomThumbPseudoLabel::kThumb1Ldr);
      ldr(rt, MemOperand(pc, 0));
    }
  }

  // =====
  void T2_Ldr(Register rt, CustomThumbPseudoLabel *label) {
    if (label->is_bound()) {
      const int64_t dest = label->pos() - buffer_.Size();
      t2_ldr(rt, MemOperand(pc, dest));
    } else {
      // record this ldr, and fix later.
      label->link_to(buffer_.Size(), CustomThumbPseudoLabel::kThumb2Ldr);
      t2_ldr(rt, MemOperand(pc, 0));
    }
  }
};

// Generate the relocated instruction
Code *GenRelocateCode(uintptr_t src_pc, int count);

} // namespace arm
} // namespace zz

#endif