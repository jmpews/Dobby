#ifndef INSTRUCTION_RELOCATION_ARM_H
#define INSTRUCTION_RELOCATION_ARM_H

#include "dobby_internal.h"

#include "core/arch/arm/constants-arm.h"
#include "core/assembler/assembler-arm.h"

namespace zz {
namespace arm {

// custom thumb pseudo label for thumb/thumb2
class ThumbPseudoLabel : public AssemblerPseudoLabel {
public:
  // thumb1/thumb2 pseudo label type, only support Thumb1-Ldr | Thumb2-Ldr
  enum CustomThumbPseudoLabelType { kThumb1Ldr, kThumb2LiteralLdr };

  // fix the instruction which not link to the label yet.
  void link_confused_instructions(CodeBuffer *buffer = nullptr) {
    CodeBuffer *_buffer;
    if (buffer)
      _buffer = buffer;

    for (auto &ref_label_inst : ref_label_insts_) {

      // instruction offset to label
      const thumb2_inst_t instr = _buffer->LoadThumb2Inst(ref_label_inst.offset_);
      const thumb1_inst_t inst1 = _buffer->LoadThumb1Inst(ref_label_inst.offset_);
      const thumb1_inst_t inst2 = _buffer->LoadThumb1Inst(ref_label_inst.offset_ + sizeof(thumb1_inst_t));

      switch (ref_label_inst.type_) {
      case kThumb1Ldr: {
        UNREACHABLE();
      } break;
      case kThumb2LiteralLdr: {
        int32_t offset = relocated_pos() - ALIGN(ref_label_inst.offset_, 4) - Thumb_PC_OFFSET;
        uint32_t imm12 = offset;
        CHECK(imm12 < (1 << 12));
        uint16_t encoding = inst2 & 0xf000;
        encoding = encoding | imm12;
        _buffer->RewriteThumb1Inst(ref_label_inst.offset_, inst1 | B7); // add = (U == '1');
        _buffer->RewriteThumb1Inst(ref_label_inst.offset_ + Thumb1_INST_LEN, encoding);

        DLOG(0, "[thumb label link] insn offset %d link offset %d", ref_label_inst.offset_, offset);
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
      case kThumb2LiteralLdr: {
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

class ThumbRelocLabelEntry : public ThumbPseudoLabel {
public:
  explicit ThumbRelocLabelEntry(uint32_t data, bool used_for_branch)
      : data_size_(0), used_for_branch_(used_for_branch) {
    data_ = data;
  }

  uint32_t data() {
    return data_;
  }

  void fixup_data(uint32_t data) {
    data_ = data;
  }

  bool used_for_branch() {
    return used_for_branch_;
  }

private:
  uint32_t data_;

  int data_size_;

  bool used_for_branch_;
};

// ================================================================
// ThumbAssembler

class ThumbAssembler : public Assembler {
public:
  ThumbAssembler(void *address) : Assembler(address) {
    this->SetExecuteState(ThumbExecuteState);
  }

  ThumbAssembler(void *address, CodeBuffer *buffer) : Assembler(address, buffer) {
    this->SetExecuteState(ThumbExecuteState);
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

#if 0
    // literal ldr, base = ALIGN(pc, 4)
    if (rt.Is(pc)) {
      // TODO: convert to `GetRealizedAddress()` ???
      addr_t curr_pc = pc_offset() + (addr_t)GetRealizedAddress();
      if (curr_pc % 4) {
        t1_nop();
      }
    }
#endif

    if (offset > 0) {
      U = B7;
      imm12 = offset;
    } else {
      U = 0;
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
      U = x.offset() > 0 ? 0 : B9;
      if (x.IsPostIndex()) {
        P = 0, W = B8;
      } else if (x.IsPreIndex()) {
        P = B10, W = B8;
      }
      index = (P == B10);
      add = (U == B9);
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
    uint32_t i1 = (operand >> 22) & 0x1;
    uint32_t i2 = (operand >> 21) & 0x1;
    uint32_t imm10 = (operand >> 11) & 0x03ff;
    uint32_t imm11 = operand & 0x07ff;
    uint32_t j1 = (!(i1 ^ signbit));
    uint32_t j2 = (!(i2 ^ signbit));

    if (cond != AL) {
      UNIMPLEMENTED();
    }

    EmitInt16(0xf000 | LeftShift(signbit, 1, 10) | LeftShift(imm10, 10, 0));
    if (link) {
      // Not use LeftShift(1, 1, 14), and use B14 for accelerate
      EmitInt16(0x9000 | LeftShift(j1, 1, 13) | (LeftShift(j2, 1, 11)) | LeftShift(imm11, 11, 0) | B14);
    } else {
      EmitInt16(0x9000 | LeftShift(j1, 1, 13) | (LeftShift(j2, 1, 11)) | LeftShift(imm11, 11, 0));
    }
  }
};

// ----- next -----

class ThumbTurboAssembler : public ThumbAssembler {
public:
  ThumbTurboAssembler(void *address) : ThumbAssembler(address) {
  }

  ThumbTurboAssembler(void *address, CodeBuffer *buffer) : ThumbAssembler(address, buffer) {
  }

  ~ThumbTurboAssembler() {
  }

  void T1_Ldr(Register rt, ThumbPseudoLabel *label) {
    UNREACHABLE();

// t1_ldr: rt can't be PC register
// ===
#if 0
    if (label->is_bound()) {
      const int64_t dest = label->pos() - buffer_.Size();
      ldr(rt, MemOperand(pc, dest));
    } else {
      // record this ldr, and fix later.
      label->link_to(buffer_.Size(), ThumbPseudoLabel::kThumb1Ldr);
      ldr(rt, MemOperand(pc, 0));
    }
#endif
  }

  void T2_Ldr(Register rt, ThumbPseudoLabel *label) {
    if (label->relocated_pos()) {
      int offset = label->relocated_pos() - buffer_->GetBufferSize();
      t2_ldr(rt, MemOperand(pc, offset));
    } else {
      // record this ldr, and fix later.
      label->link_to(ThumbPseudoLabel::kThumb2LiteralLdr, 0, buffer_->GetBufferSize());
      t2_ldr(rt, MemOperand(pc, 0));
    }
  }

  void AlignThumbNop() {
    addr32_t pc = this->GetCodeBuffer()->GetBufferSize() + (addr32_t)GetRealizedAddress();
    if (pc % Thumb2_INST_LEN) {
      t1_nop();
    } else {
    }
  }

  // ================================================================
  // ThumbRelocLabelEntry

  void ThumbPseudoBind(ThumbPseudoLabel *label) {
    if (label->relocated_pos()) {
      const addr32_t bound_pc = buffer_->GetBufferSize();
      label->bind_to(bound_pc);
    }
    // If some instructions have been wrote, before the label bound, we need link these `confused` instructions
    if (label->has_confused_instructions()) {
      label->link_confused_instructions(this->GetCodeBuffer());
    }
  }

  void RelocBindFixup(ThumbRelocLabelEntry *label) {
    buffer_->RewriteAddr(label->relocated_pos(), label->data());
  }

  // ----- next -----

  void PseudoBind(AssemblerPseudoLabel *label) {
    const addr_t bound_pc = buffer_->GetBufferSize();
    label->bind_to(bound_pc);
    // If some instructions have been wrote, before the label bound, we need link these `confused` instructions
    if (label->has_confused_instructions()) {
      label->link_confused_instructions(GetCodeBuffer());
    }
  }

  void RelocBind() {
    for (auto *data_label : data_labels_) {
      PseudoBind(data_label);
      buffer_->Emit(data_label->data());
    }
  }

  void AppendRelocLabelEntry(RelocLabelEntry *label) {
    data_labels_.push_back(label);
  }

private:
  std::vector<RelocLabelEntry *> data_labels_;
};

#if 0
void GenRelocateCodeAndBranch(void *buffer, AssemblyCode *origin, AssemblyCode *relocated);
#endif

} // namespace arm
} // namespace zz

#endif
