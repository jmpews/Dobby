#ifndef INSTRUCTION_RELOCATION_ARM_H
#define INSTRUCTION_RELOCATION_ARM_H

#include "core/arch/arm/constants-arm.h"
#include "ExecMemory/AssemblyCode.h"

#include "core/modules/assembler/assembler-arm.h"

#include "logging/check_logging.h"

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

    PseudoLabelInstruction *instruction;
    LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(&instructions_);
    while ((instruction = reinterpret_cast<PseudoLabelInstruction *>(iter->getNextObject())) != NULL) {
      // instruction offset to label
      int32_t offset            = pos() - instruction->position_ - Thumb_PC_OFFSET;
      const thumb2_inst_t instr = _buffer->LoadThumb2Inst(instruction->position_);
      const thumb1_inst_t inst1 = _buffer->LoadThumb1Inst(instruction->position_);
      const thumb1_inst_t inst2 = _buffer->LoadThumb1Inst(instruction->position_ + sizeof(thumb1_inst_t));

      switch (instruction->type_) {
      case kThumb1Ldr: {
        UNREACHABLE();
      } break;
      case kThumb2Ldr: {
        uint32_t imm12 = offset;
        CHECK(imm12 < (1 << 12));
        uint16_t encoding = inst2 & 0xf000;
        encoding          = encoding | imm12;
        _buffer->RewriteThumb1Inst(instruction->position_, inst1 | B7); // add = (U == '1');
        _buffer->RewriteThumb1Inst(instruction->position_ + Thumb1_INST_LEN, encoding);
      } break;
      default:
        UNREACHABLE();
        break;
      }
    }

#if 0
    for (auto instruction : instructions_) {
      // instruction offset to label
      int32_t offset      = pos() - instruction.position_ - Thumb_PC_OFFSET;
      const int32_t instr  = _buffer->Load<int32_t>(instruction.position_);
      const int16_t inst1 = _buffer->Load<int16_t>(instruction.position_);
      const int16_t inst2 = _buffer->Load<int16_t>(instruction.position_ + sizeof(int16_t));

      switch (instruction.type_) {
      case kThumb1Ldr: {
        UNREACHABLE();
      } break;
      case kThumb2Ldr: {
        uint32_t imm12 = offset;
        CHECK(imm12 < (1 << 12));
        uint16_t encoding = inst2 & 0xf000;
        encoding          = encoding | imm12;
        _buffer->Store<int16_t>(instruction.position_, inst1 | B7); // add = (U == '1');
        _buffer->Store<int16_t>(instruction.position_ + Thumb1_INST_LEN, encoding);
      } break;
      default:
        UNREACHABLE();
        break;
      }
    }
#endif
  }
};

class CustomThumbAssembler : public Assembler {
public:
  CustomThumbAssembler(void *address) : Assembler(address) {
  }

  void EmitInt16(int16_t val) {
    buffer_->Emit16(val);
  }

  void Emit2Int16(int16_t val1, int16_t val2) {
    EmitInt16(val1);
    EmitInt16(val2);
  }

  void EmitAddress(uint32_t value) {
    buffer_->Emit32(value);
  }

  // =====
  void t1_nop() {
    EmitInt16(0xbf00);
  }
  void t1_b(int32_t imm) {
    ASSERT(CheckSignLength(imm, 12));
    ASSERT(CheckAlign(imm, 2));

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
    // WARNNING: literal ldr, base = ALIGN(pc, 4)
    EmitThumb2LoadStore(true, dst, src);
  }

private:
  void EmitThumb2LoadLiteral(Register rt, const MemOperand x) {
    bool add = true;
    uint32_t U, imm12;
    int32_t offset = x.offset();

    // literal ldr, base = ALIGN(pc, 4)
    if(rt.Is(pc)) {
      // TODO: convert to `GetRealizeAddress()` ???
      addr_t curr_pc = pc_offset() + (addr_t)GetRealizeAddress();
      if (curr_pc % 4) {
        t1_nop();
      }
    }

    if (offset > 0) {
      U     = B7;
      imm12 = offset;
    } else {
      U     = 0;
      imm12 = -offset;
    }
    EmitInt16(0xf85f | U);
    EmitInt16(0x0 | (rt.code() << 12) | imm12);
  }
  void EmitThumb2LoadStore(bool load, Register rt, const MemOperand x) {
    if (x.rn().Is(pc)) {
      EmitThumb2LoadLiteral(rt, x);
      return;
    }

    bool index, add, wback;
    if (x.IsRegisterOffset() && x.offset() >= 0) {
      index = true, add = true, wback = false;
      uint32_t imm12 = x.offset();
      EmitInt16(0xf8d0 | (x.rn().code() << 0));
      EmitInt16(0x0 | (rt.code() << 12) | imm12);
    } else {
      // use bit accelerate
      uint32_t P = 0, W = 0, U = 0;
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
      EmitInt16(0xf850 | (x.rn().code() << 0));
      EmitInt16(0x0800 | (rt.code() << 12) | P | U | W | imm8);
    }
  }

  // =====
  void EmitThumb2Branch(Condition cond, int32_t imm, bool link) {
    uint32_t operand = imm >> 1;
    ASSERT(CheckSignLength(operand, 25));
    ASSERT(CheckAlign(operand, 2));

    uint32_t signbit = (imm >> 31) & 0x1;
    uint32_t i1      = (operand >> 22) & 0x1;
    uint32_t i2      = (operand >> 21) & 0x1;
    uint32_t imm10   = (operand >> 11) & 0x03ff;
    uint32_t imm11   = operand & 0x07ff;
    uint32_t j1      = (!(i1 ^ signbit));
    uint32_t j2      = (!(i2 ^ signbit));

    if (cond != AL) {
      UNIMPLEMENTED();
    }

    EmitInt16(0xf000 | LFT(signbit, 1, 10) | LFT(imm10, 10, 0));
    if (link) {
      // Not use LFT(1, 1, 14), and use B14 for accelerate
      EmitInt16(0x9000 | LFT(j1, 1, 13) | (LFT(j2, 1, 11)) | LFT(imm11, 11, 0) | B14);
    } else {
      EmitInt16(0x9000 | LFT(j1, 1, 13) | (LFT(j2, 1, 11)) | LFT(imm11, 11, 0));
    }
  }
};

class ThumbTurboAssembler : public CustomThumbAssembler {
public:
  ThumbTurboAssembler(void *address) : CustomThumbAssembler(address) {
  }

  void T1_Ldr(Register rt, CustomThumbPseudoLabel *label) {
    UNREACHABLE();

// t1_ldr: rt can't be PC register
// ===
#if 0
    if (label->is_bound()) {
      const int64_t dest = label->pos() - buffer_.Size();
      ldr(rt, MemOperand(pc, dest));
    } else {
      // record this ldr, and fix later.
      label->link_to(buffer_.Size(), CustomThumbPseudoLabel::kThumb1Ldr);
      ldr(rt, MemOperand(pc, 0));
    }
#endif
  }

  void T2_Ldr(Register rt, CustomThumbPseudoLabel *label) {
    if (label->is_bound()) {
      const int64_t dest = label->pos() - buffer_->getSize();
      t2_ldr(rt, MemOperand(pc, dest));
    } else {
      // record this ldr, and fix later.
      label->link_to(buffer_->getSize(), CustomThumbPseudoLabel::kThumb2Ldr);
      t2_ldr(rt, MemOperand(pc, 0));
    }
  }

  void AlignThumbNop() {
    int pc_offset = this->GetCodeBuffer()->getSize();
    if (pc_offset % Thumb2_INST_LEN) {
      t1_nop();
    } else {
    }
  }

  void CustomThumbPseudoBind(CustomThumbPseudoLabel *label) {
    const uintptr_t bound_pc = buffer_->getSize();
    label->bind_to(bound_pc);
    // If some instructions have been wrote, before the label bound, we need link these `confused` instructions
    if (label->has_confused_instructions()) {
      label->link_confused_instructions(this->GetCodeBuffer());
    }
  }

private:
  // void *released_address_;
};

// Generate the relocated instruction
void GenRelocateCode(void *buffer, AssemblyCode *origin, AssemblyCode *relocated);

} // namespace arm
} // namespace zz

#endif
