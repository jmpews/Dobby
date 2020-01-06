#ifndef CORE_ASSEMBLER_ARM_H
#define CORE_ASSEMBLER_ARM_H

#include "core/arch/arm/constants-arm.h"
#include "core/arch/arm/registers-arm.h"

#include "core/modules/assembler/assembler.h"

#include "ExecMemory/CodeBuffer/code-buffer-arm.h"

#include "logging/check_logging.h"

#include "core/utility.h"
#include "logging/logging.h"

#include "stdcxx/LiteMutableArray.h"
#include "stdcxx/LiteIterator.h"

namespace zz {
namespace arm {

#define ThumbAlign(x) (((uint32_t)-2) & x)

// ARM design had a 3-stage pipeline (fetch-decode-execute)
#define ARM_PC_OFFSET 8
#define Thumb_PC_OFFSET 4

// define instruction length
#define ARM_INST_LEN 4
#define Thumb1_INST_LEN 2
#define Thumb2_INST_LEN 4

// Thumb instructions address is odd
#define THUMB_ADDRESS_FLAG 1

constexpr Register TMP0 = r12;

// ===== PseudoLabel =====

class PseudoLabel : public Label {
public:
  enum PseudoLabelType { kLdrLiteral };

  typedef struct _PseudoLabelInstruction {
    int position_;
    int type_;
  } PseudoLabelInstruction;

  bool has_confused_instructions() {
    return instructions_->getCount() > 0;
  }

  void link_confused_instructions(CodeBuffer *buffer = nullptr) {
    CodeBuffer *_buffer;
    if (buffer)
      _buffer = buffer;

    PseudoLabelInstruction *instruction;
    LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(instructions_);
    while ((instruction = reinterpret_cast<PseudoLabelInstruction *>(iter->getNextObject())) != NULL) {
      int32_t offset       = pos() - instruction->position_;
      const int32_t inst32 = _buffer->LoadARMInst(instruction->position_);
      int32_t encoded      = 0;

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

  void link_to(int pos, int type) {
    PseudoLabelInstruction *instruction = new PseudoLabelInstruction;
    instruction->position_              = pos;
    instruction->type_                  = type;
    instructions_->pushObject((LiteObject *)instruction);
  }

protected:
  // std::vector<PseudoLabelInstruction> instructions_;
  LiteMutableArray *instructions_;
};

// ===== Operand =====

class Operand {
public:
  explicit Operand(int immediate) : immediate_(immediate), rm_(no_reg), rs_(no_reg) {
    ASSERT(immediate < (1 << kImmed8Bits));
    type_     = 1;
    encoding_ = immediate;
  }
  explicit Operand(Register rm) : immediate_(-1), rm_(rm), rs_(no_reg) {
    type_     = 0;
    encoding_ = static_cast<uint32_t>(rm.code());
  }
  explicit Operand(Register rm, Shift shift, int shift_imm)
      : immediate_(-1), rm_(rm), rs_(no_reg), shift_(shift), shift_imm_(shift & 31) {
    UNREACHABLE();

    ASSERT(shift_imm < (1 << kShiftImmBits));
    type_ = 0;
    encoding_ =
        shift_imm << kShiftImmShift | static_cast<uint32_t>(shift) << kShiftShift | static_cast<uint32_t>(rm.code());
  }
  explicit Operand(Register rm, Shift shift, Register rs) : immediate_(-1), rm_(rm), rs_(rs), shift_(shift) {
    UNREACHABLE();

    type_     = 0;
    encoding_ = static_cast<uint32_t>(rs.code()) << kShiftRegisterShift | static_cast<uint32_t>(shift) << kShiftShift |
                (1 << 4) | static_cast<uint32_t>(rm.code());
  }

private:
  Register rm_;
  Register rs_;
  Shift shift_;
  int shift_imm_;
  int32_t immediate_;

  uint32_t type_; // Encodes the type field (bits 27-25) in the instruction.
  uint32_t encoding_;

  friend class OpEncode;
};

// ===== MemOperand =====

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
  Register rn_;    // base
  Register rm_;    // register offset
  int32_t offset_; // valid if rm_ == no_reg
  Shift shift_;
  int shift_imm_; // valid if rm_ != no_reg && rs_ == no_reg
  AddrMode am_;   // bits P, U, and W

  friend class OpEncode;
};

// ===== OpEncode =====

class OpEncode {
public:
  static inline uint32_t Rd(Register rd) {
    // ASSERT(rd.code() < 16);
    return static_cast<uint32_t>(rd.code()) << kRdShift;
  }

  static inline uint32_t Rm(Register rm) {
    // ASSERT(rm < 16);
    return static_cast<uint32_t>(rm.code()) << kRmShift;
  }

  static inline uint32_t Rn(Register rn) {
    // ASSERT(rn < 16);
    return static_cast<uint32_t>(rn.code()) << kRnShift;
  }

  static inline uint32_t Rs(Register rs) {
    // ASSERT(rs < 16);
    return static_cast<uint32_t>(rs.code()) << kRsShift;
  }

  // ===
  static inline uint32_t MemOperand(const MemOperand x) {
    uint32_t encoding = 0;
    if (x.rm_.code() == no_reg.code()) {
      if (x.offset_ < 0) {
        encoding = (x.am_ ^ (1 << kUShift)) | -x.offset_; // Flip U to adjust sign.
      } else {
        encoding = x.am_ | x.offset_;
      }
      encoding |= OpEncode::Rn(x.rn_);
    } else {
      encoding |= B25;
      UNREACHABLE();
    }
    return encoding;
  }

  static inline uint32_t Operand(const Operand o) {
    uint32_t encoding = 0;

    // Immeidate
    if (o.rm_.code() == no_reg.code()) {
      encoding = o.immediate_;
      encoding |= B25;
    } else if (o.rm_.code() != no_reg.code()) {
      encoding = static_cast<uint32_t>(o.rm_.code());
    } else {
      UNREACHABLE();
    }
    return encoding;
  }

  static uint32_t ImmeidateChecked(uint32_t imm, uint len) {
    // TODO: uint32_t 0xffffffff = -1
    if (imm > (1 << len)) {
      FATAL("exit.");
    }
    return imm;
  }
};

// ===== Assembler =====

class Assembler : public AssemblerBase {
public:
  Assembler(void *address) : AssemblerBase(address) {
    buffer_ = new CodeBuffer(32);
    DLOG("[*] Assembler buffer at %p\n", (CodeBufferBase *)buffer_->getRawBuffer());
  }

  ~Assembler() {
    buffer_->release();
  }

public:
  void CommitRealizeAddress(void *address) {
    DCHECK_EQ(0, reinterpret_cast<uint64_t>(address) % 4);
    AssemblerBase::CommitRealizeAddress(address);
  }

  void EmitARMInst(arm_inst_t instr);

  void EmitAddress(uint32_t value);

  void sub(Register dst, Register src1, const Operand &src2, Condition cond = AL) {
    EmitType01(cond, SUB, 0, dst, src1, src2);
  }
  void add(Register dst, Register src1, const Operand &src2, Condition cond = AL) {
    EmitType01(cond, ADD, 0, dst, src1, src2);
  }

  void ldr(Register dst, const MemOperand &src, Condition cond = AL) {
    EmitMemOp(cond, true, false, dst, src);
  }
  void str(Register src, const MemOperand &dst, Condition cond = AL) {
    EmitMemOp(cond, false, false, src, dst);
  }

  void mov(Register dst, const Operand &src, Condition cond = AL) {
    EmitType01(cond, MOV, 0, dst, no_reg, src);
  }
  void mov(Register dst, Register src, Condition cond = AL) {
    mov(dst, Operand(src), AL);
  }

  // Branch instructions.
  void b(int branch_offset, Condition cond = AL) {
    EmitType5(cond, branch_offset, false);
  }
  void bl(int branch_offset, Condition cond = AL) {
    EmitType5(cond, branch_offset, true);
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

private:
  void EmitType01(Condition cond, Opcode opcode, int set_cc, const Register rd, Register rn, Operand o) {
    ASSERT(rd != no_reg);
    ASSERT(cond != kNoCondition);

    int32_t encoding = (static_cast<int32_t>(cond) << kConditionShift) |
                       (static_cast<int32_t>(opcode) << kOpcodeShift) | (set_cc << kSShift);
    encoding = encoding | (rn.Is(no_reg) ? 0 : OpEncode::Rn(rn)) | OpEncode::Rd(rd) | OpEncode::Operand(o);
    buffer_->EmitARMInst(encoding);
  }
  void EmitType5(Condition cond, int32_t offset, bool link) {
    ASSERT(cond != kNoCondition);
    int32_t encoding = (static_cast<int32_t>(cond) << kConditionShift) | LFT(5, 3, 25) | ((link ? 1 : 0) << kLinkShift);
    int32_t imm24    = bits(offset >> 2, 0, 23);
    ASSERT(CheckSignLength(imm24, 24));
    buffer_->EmitARMInst(imm24 | encoding);
  }

  // load store operation
  void EmitMemOp(Condition cond, bool load, bool byte, const Register rd, const MemOperand x) {
    ASSERT(rd != no_reg);
    ASSERT(cond != kNoCondition);

    int32_t encoding = (static_cast<int32_t>(cond) << kConditionShift) | B26 | (load ? L : 0) | (byte ? B : 0);
    encoding         = encoding | OpEncode::Rd(rd) | OpEncode::MemOperand(x);
    buffer_->EmitARMInst(encoding);
  }

private:
  // void *released_address_;
};

// ===== TurboAssembler =====

class TurboAssembler : public Assembler {
public:
  TurboAssembler(void *address) : Assembler(address) {
  }

  void Ldr(Register rt, PseudoLabel *label) {
    if (label->is_bound()) {
      const int64_t dest = label->pos() - buffer_->getSize();
      ldr(rt, MemOperand(pc, dest));
    } else {
      // record this ldr, and fix later.
      label->link_to(buffer_->getSize(), PseudoLabel::kLdrLiteral);
      ldr(rt, MemOperand(pc, 0));
    }
  }

  void PseudoBind(PseudoLabel *label) {
    const uint32_t bound_pc = buffer_->getSize();
    label->bind_to(bound_pc);
    // If some instructions have been wrote, before the label bound, we need link these `confused` instructions
    if (label->has_confused_instructions()) {
      label->link_confused_instructions(this->GetCodeBuffer());
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
};

} // namespace arm
} // namespace zz

#endif
