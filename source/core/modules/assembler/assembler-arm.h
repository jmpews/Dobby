#ifndef CORE_ASSEMBLER_ARM_H
#define CORE_ASSEMBLER_ARM_H

#include "common/headers/common_header.h"

#include "core/arch/arm/constants-arm.h"
#include "core/arch/arm/registers-arm.h"
#include "core/modules/assembler/assembler.h"

#include "CodeBuffer/code-buffer-arm.h"

#include "xnucxx/LiteMutableArray.h"
#include "xnucxx/LiteIterator.h"

namespace zz {
namespace arm {

// ARM design had a 3-stage pipeline (fetch-decode-execute)
#define ARM_PC_OFFSET   8
#define Thumb_PC_OFFSET 4

// define instruction length
#define ARM_INST_LEN    4
#define Thumb1_INST_LEN 2
#define Thumb2_INST_LEN 4

// Thumb instructions address is odd
#define THUMB_ADDRESS_FLAG 1

constexpr Register TMP_REG_0 = r12;

constexpr Register VOLATILE_REGISTER = r12;

// ===== PseudoLabel =====

class PseudoLabel : public Label {
public:
  enum PseudoLabelType { kLdrLiteral };

  typedef struct _PseudoLabelInstruction {
    int position_;
    int type_;
  } PseudoLabelInstruction;

public:
  PseudoLabel(void) {
    instructions_.initWithCapacity(8);
  }

  ~PseudoLabel(void) {
    for (size_t i = 0; i < instructions_.getCount(); i++) {
      PseudoLabelInstruction *item = (PseudoLabelInstruction *)instructions_.getObject(i);
      delete item;
    }
  }

  bool has_confused_instructions() {
    return instructions_.getCount() > 0;
  }

  void link_confused_instructions(CodeBuffer *buffer = nullptr) {
    if (!buffer)
      UNREACHABLE();
    CodeBuffer *_buffer = buffer;

    for (size_t i = 0; i < instructions_.getCount(); i++) {
      PseudoLabelInstruction *instruction = (PseudoLabelInstruction *)instructions_.getObject(i);

      int32_t       offset  = pos() - instruction->position_;
      const int32_t inst32  = _buffer->LoadARMInst(instruction->position_);
      int32_t       encoded = 0;

      switch (instruction->type_) {
      case kLdrLiteral: {
        encoded        = inst32 & 0xfffff000;
        uint32_t imm12 = offset - ARM_PC_OFFSET;
        ASSERT(CheckSignLength(imm12));
        encoded = encoded | imm12;
      } break;
      default:
        UNREACHABLE();
        break;
      }
      _buffer->RewriteARMInst(instruction->position_, encoded);
    }
  };

  // compatible for thumb with int type
  void link_to(int pos, int type) {
    PseudoLabelInstruction *instruction = new PseudoLabelInstruction;
    instruction->position_              = pos;
    instruction->type_                  = type;
    instructions_.pushObject((LiteObject *)instruction);
  }

protected:
  LiteMutableArray instructions_;
};

// reloc
class RelocLabelEntry : public PseudoLabel {
public:
  explicit RelocLabelEntry(uint32_t data) : data_size_(0) {
    data_ = data;
  }

  uint32_t data() {
    return data_;
  }

  void fixup_data(uint32_t data) {
    data_ = data;
  }

private:
  uint32_t data_;

  int data_size_;
};

// ================================================================
// Operand

class Operand {
public:
  explicit Operand(int immediate) : imm_(immediate), rm_(no_reg), rs_(no_reg) {
  }
  explicit Operand(Register rm) : imm_(-1), rm_(rm), rs_(no_reg) {
  }
  explicit Operand(Register rm, Shift shift, int shift_imm)
      : imm_(-1), rm_(rm), rs_(no_reg), shift_(shift), shift_imm_(shift & 31) {
  }
  explicit Operand(Register rm, Shift shift, Register rs) : imm_(-1), rm_(rm), rs_(rs), shift_(shift) {
  }

public:
  uint32_t GetImmediate() const {
    return imm_;
  }

private:
  Register rm_;
  Register rs_;

  Shift shift_;
  int   shift_imm_;

  uint32_t imm_;

private:
  friend class EncodeUtility;
};

// ================================================================
// MemOperand

class MemOperand {
public:
  explicit MemOperand(Register rn, int32_t offset = 0, AddrMode am = Offset)
      : rn_(rn), rm_(no_reg), offset_(offset), am_(am) {
  }

  explicit MemOperand(Register rn, Register rm, AddrMode am = Offset)
      : rn_(rn), rm_(rm), shift_(LSL), shift_imm_(0), am_(am) {
    UNREACHABLE();
  }

  explicit MemOperand(Register rn, Register rm, Shift shift, int shift_imm, AddrMode am = Offset)
      : rn_(rn), rm_(rm), shift_(shift), shift_imm_(shift_imm & 31), am_(am) {
    UNREACHABLE();
  }

  const Register &rn() const {
    return rn_;
  }
  const Register &rm() const {
    return rm_;
  }
  int32_t offset() const {
    return offset_;
  }

  bool IsImmediateOffset() const {
    return (am_ == Offset);
  }
  bool IsRegisterOffset() const {
    return (am_ == Offset);
  }
  bool IsPreIndex() const {
    return am_ == PreIndex;
  }
  bool IsPostIndex() const {
    return am_ == PostIndex;
  }

private:
  Register rn_; // base
  Register rm_; // register offset

  int32_t offset_; // valid if rm_ == no_reg

  Shift shift_;
  int   shift_imm_; // valid if rm_ != no_reg && rs_ == no_reg

  AddrMode am_; // bits P, U, and W

  friend class EncodeUtility;
};

class EncodeUtility {
public:
  static inline uint32_t Rd(Register rd) {
    return static_cast<uint32_t>(rd.code()) << 12;
  }

  static inline uint32_t Rt(Register rt) {
    return static_cast<uint32_t>(rt.code()) << 12;
  }

  static inline uint32_t Rm(Register rm) {
    return static_cast<uint32_t>(rm.code()) << 0;
  }

  static inline uint32_t Rn(Register rn) {
    return static_cast<uint32_t>(rn.code()) << 16;
  }

  // ===
  static inline uint32_t MemOperand(const MemOperand operand) {
    uint32_t encoding = 0;
    if (!operand.rm_.IsValid()) {
      if (operand.offset_ < 0) {
        encoding = (operand.am_ ^ (1 << 23)) | (-operand.offset_); // Flip U to adjust sign.
      } else {
        encoding = operand.am_ | operand.offset_;
      }
      encoding |= EncodeUtility::Rn(operand.rn_);
    } else {
      UNREACHABLE();
    }
    return encoding;
  }

  static inline uint32_t Operand(const Operand operand) {
    uint32_t encoding = 0;
    if (operand.rm_.IsValid()) {
      encoding = operand.GetImmediate();
    } else {
      encoding = static_cast<uint32_t>(operand.rm_.code());
    }

    return encoding;
  }
};

// ================================================================
// Assembler

enum ExecuteState { ARMExecuteState, ThumbExecuteState };

class Assembler : public AssemblerBase {
private:
  ExecuteState execute_state_;

public:
  Assembler(void *address) : AssemblerBase(address) {
    execute_state_ = ARMExecuteState;
    buffer_        = new CodeBuffer(64);
    DLOG(0, "Assembler buffer at %p", (CodeBufferBase *)buffer_->getRawBuffer());
  }

  // shared_ptr is better choice
  // but we can't use it at kernelspace
  Assembler(void *address, CodeBuffer *buffer) : AssemblerBase(address) {
    execute_state_ = ARMExecuteState;
    buffer_        = buffer;
    DLOG(0, "Assembler buffer at %p", (CodeBufferBase *)buffer_->getRawBuffer());
  }

  ~Assembler() {
    if (buffer_)
      delete buffer_;
  }

  void ClearCodeBuffer() {
    buffer_ = NULL;
  }

public:
  void SetExecuteState(ExecuteState state) {
    execute_state_ = state;
  }
  ExecuteState GetExecuteState() {
    return execute_state_;
  }

  void CommitRealizeAddress(void *address) {
    DCHECK_EQ(0, reinterpret_cast<uint64_t>(address) % 4);
    AssemblerBase::CommitRealizeAddress(address);
  }

  void EmitARMInst(arm_inst_t instr);

  void EmitAddress(uint32_t value);

public:
  void sub(Register rd, Register rn, const Operand &operand) {
    sub(AL, rd, rn, operand);
  }

  void sub(Condition cond, Register rd, Register rn, const Operand &operand) {
    if (rn.Is(pc))
      UNIMPLEMENTED();

    uint32_t imm = operand.GetImmediate();
    buffer_->EmitARMInst(0x024d0000U | (cond << 28) | (rd.code() << 12) | (rn.code() << 16) | imm);
  }

  void add(Register rd, Register rn, const Operand &operand) {
    sub(AL, rd, rn, operand);
  }

  void add(Condition cond, Register rd, Register rn, const Operand &operand) {
    if (rn.Is(pc))
      UNIMPLEMENTED();

    uint32_t imm = operand.GetImmediate();
    buffer_->EmitARMInst(0x02900000U | (cond << 28) | (rd.code() << 12) | (rn.code() << 16) | imm);
  }

  void ldr(Register rt, const MemOperand &operand) {
    ldr(AL, rt, operand);
  }

  void ldr(Condition cond, Register rt, const MemOperand &operand) {
    uint32_t encoding = 0x05100000U;
    encoding |= (cond << kConditionShift);
    encoding |= EncodeUtility::Rt(rt) | EncodeUtility::MemOperand(operand);
    buffer_->EmitARMInst(encoding);
  }

  void str(Register rt, const MemOperand &operand) {
    ldr(AL, rt, operand);
  }

  void str(Condition cond, Register rt, const MemOperand &operand) {
    uint32_t encoding = 0x05000000U;
    encoding |= (cond << kConditionShift);
    encoding |= EncodeUtility::Rt(rt) | EncodeUtility::MemOperand(operand);
    buffer_->EmitARMInst(encoding);
  }

  void mov(Register rd, const Operand &operand) {
    mov(AL, rd, operand);
  }

  void mov(Condition cond, Register rd, const Operand &operand) {
    uint32_t encoding = 0x01a00000U;
    encoding |= (cond << kConditionShift);
    encoding |= EncodeUtility::Rd(rd) | EncodeUtility::Operand(operand);
    buffer_->EmitARMInst(encoding);
  }

  // Branch instructions.
  void b(int branch_offset) {
    b(AL, branch_offset);
  }
  void b(Condition cond, int branch_offset) {
    uint32_t encoding = 0xb000000;
    encoding |= (cond << kConditionShift);
    uint32_t imm24 = bits(branch_offset >> 2, 0, 23);
    encoding |= imm24;
    buffer_->EmitARMInst(encoding);
  }

  void bl(int branch_offset) {
    bl(AL, branch_offset);
  }
  void bl(Condition cond, int branch_offset) {
    uint32_t encoding = 0xa000000;
    encoding |= (cond << kConditionShift);
    uint32_t imm24 = bits(branch_offset >> 2, 0, 23);
    encoding |= imm24;
    buffer_->EmitARMInst(encoding);
  }

  void blx(int branch_offset) {
    UNIMPLEMENTED();
  }
  void blx(Register target, Condition cond = AL) {
    UNIMPLEMENTED();
  }
  void bx(Register target, Condition cond = AL) {
    UNIMPLEMENTED();
  }

}; // namespace arm

// ================================================================
// TurboAssembler

class TurboAssembler : public Assembler {
public:
  TurboAssembler(void *address) : Assembler(address) {
    data_labels_ = NULL;
  }

  TurboAssembler(void *address, CodeBuffer *buffer) : Assembler(address, buffer) {
    data_labels_ = NULL;
  }

  void Ldr(Register rt, PseudoLabel *label) {
    if (label->is_bound()) {
      int offset = label->pos() - buffer_->getSize();
      ldr(rt, MemOperand(pc, offset));
    } else {
      // record this ldr, and fix later.
      label->link_to(buffer_->getSize(), PseudoLabel::kLdrLiteral);
      ldr(rt, MemOperand(pc, 0));
    }
  }

  void CallFunction(ExternalReference function) {
    // trick: use bl to replace lr register
    bl(0);
    b(4);
    ldr(pc, MemOperand(pc, -4));
    buffer_->Emit32((uint32_t)function.address());
  }

  void Move32Immeidate(Register rd, const Operand &x, Condition cond = AL) {
  }

  // ================================================================
  // RelocLabelEntry

  void PseudoBind(PseudoLabel *label) {
    if (label->is_unused() == true) {
      const uint32_t bound_pc = buffer_->getSize();
      label->bind_to(bound_pc);
    }
    // If some instructions have been wrote, before the label bound, we need link these `confused` instructions
    if (label->has_confused_instructions()) {
      label->link_confused_instructions(this->GetCodeBuffer());
    }
  }

  void RelocBindFixup(RelocLabelEntry *label) {
    buffer_->RewriteAddr(label->pos(), label->data());
  }

  void RelocBind() {
    if (data_labels_ == NULL)
      return;
    for (size_t i = 0; i < data_labels_->getCount(); i++) {
      RelocLabelEntry *label = (RelocLabelEntry *)data_labels_->getObject(i);
      PseudoBind(label);
      EmitAddress(label->data());
    }
  }

  void AppendRelocLabelEntry(RelocLabelEntry *label) {
    if (data_labels_ == NULL) {
      data_labels_ = new LiteMutableArray(8);
    }
    data_labels_->pushObject((LiteObject *)label);
  }

  LiteMutableArray *GetLabels() {
    return data_labels_;
  }

private:
  LiteMutableArray *data_labels_;
};

} // namespace arm
} // namespace zz

#endif
