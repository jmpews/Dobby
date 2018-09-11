#ifndef ZZ_ARCHITECTURE_ARCH_ARM64_ASSEMBLER_H_
#define ZZ_ARCHITECTURE_ARCH_ARM64_ASSEMBLER_H_

#include "vm_core/arch/arm64/constants-arm64.h"
#include "vm_core/arch/arm64/instructions-arm64.h"
#include "vm_core/arch/arm64/registers-arm64.h"

#include "vm_core/modules/assembler/assembler.h"

#include "vm_core/macros.h"
#include "vm_core/base/code-buffer.h"
#include "vm_core/utils.h"

#include <assert.h>

namespace zz {
namespace arm64 {

class PseudoLabel : public Label {
  enum PseudoLabelType { kLdrPseudoLabel };

  typedef struct _PseudoLabelInstruction {
    int position_;
    PseudoLabelType type_;
  } PseudoLabelInstruction;

public:
  bool has_confused_instructions() {
    return instructions_.size() > 0;
  }

  void link_confused_instructions(CodeBuffer *buffer = nullptr) {
    CodeBuffer *_buffer;
    if (buffer)
      _buffer = buffer;

    for (auto instruction : instructions_) {
      int32_t offset       = instruction.position_ - pos();
      const int32_t inst32 = _buffer->Load32(instruction.position_);
      int32_t encoded      = 0;

      switch (instruction.type_) {
      case kLdrPseudoLabel: {
        encoded = (inst32 & 0xfff) | offset;
      } break;
      default:
        break;
      }
      _buffer->Store32(instruction.position_, encoded);
    }
  };

private:
  // From a design perspective, these fix-function write as callback, maybe beeter.
  void FixLdr(PseudoLabelInstruction *instruction){
      // dummy
  };

private:
  std::vector<PseudoLabelInstruction> instructions_;
};

class Operand {
public:
  inline Operand(Register reg, Shift shift = LSL, int32_t imm = 0)
      : immediate_(0), reg_(reg), shift_(shift), extend_(NO_EXTEND), shift_extent_imm_(imm) {
  }
  inline Operand(Register reg, Extend extend, int32_t imm = 0)
      : immediate_(0), reg_(reg), shift_(NO_SHIFT), extend_(extend), shift_extent_imm_(imm) {
  }

  bool IsShiftedRegister() const {
    return /* reg_.IsValid() && */ (shift_ != NO_SHIFT);
  }

  bool IsExtendedRegister() const {
    return /* reg_.IsValid() && */ (extend_ != NO_EXTEND);
  }

  Register reg() const {
    DCHECK(IsShiftedRegister() || IsExtendedRegister());
    return reg_;
  }

  Shift shift() const {
    DCHECK(IsShiftedRegister());
    return shift_;
  }

  Extend extend() const {
    DCHECK(IsExtendedRegister());
    return extend_;
  }

  int32_t shift_extend_imm() const {
    return shift_extent_imm_;
  }

private:
  int64_t immediate_;
  Register reg_;
  Shift shift_;
  Extend extend_;
  int32_t shift_extent_imm_;
};

class MemOperand {
public:
  inline explicit MemOperand(Register base, int64_t offset = 0, AddrMode addrmode = Offset)
      : base_(base), regoffset_(InvalidRegister), offset_(offset), addrmode_(addrmode), shift_(NO_SHIFT),
        extend_(NO_EXTEND), shift_extend_imm_(0) {
  }

  inline explicit MemOperand(Register base, Register regoffset, Extend extend, unsigned extend_imm)
      : base_(base), regoffset_(regoffset), offset_(0), addrmode_(Offset), shift_(NO_SHIFT), extend_(extend),
        shift_extend_imm_(extend_imm) {
  }

  inline explicit MemOperand(Register base, Register regoffset, Shift shift = LSL, unsigned shift_imm = 0)
      : base_(base), regoffset_(regoffset), offset_(0), addrmode_(Offset), shift_(shift), extend_(NO_EXTEND),
        shift_extend_imm_(shift_imm) {
  }

  inline explicit MemOperand(Register base, const Operand &offset, AddrMode addrmode = Offset)
      : base_(base), regoffset_(InvalidRegister), addrmode_(addrmode) {
    if (offset.IsShiftedRegister()) {
      regoffset_        = offset.reg();
      shift_            = offset.shift();
      shift_extend_imm_ = offset.shift_extend_imm();

      extend_ = NO_EXTEND;
      offset_ = 0;
    } else if (offset.IsExtendedRegister()) {
      regoffset_        = offset.reg();
      extend_           = offset.extend();
      shift_extend_imm_ = offset.shift_extend_imm();

      shift_  = NO_SHIFT;
      offset_ = 0;
    }
  }

  const Register &base() const {
    return base_;
  }
  const Register &regoffset() const {
    return regoffset_;
  }
  int64_t offset() const {
    return offset_;
  }
  AddrMode addrmode() const {
    return addrmode_;
  }
  Shift shift() const {
    return shift_;
  }
  Extend extend() const {
    return extend_;
  }
  unsigned shift_extend_imm() const {
    return shift_extend_imm_;
  }
  bool IsImmediateOffset() const {
    return (addrmode_ == Offset);
  }
  bool IsRegisterOffset() const {
    return (addrmode_ == Offset);
  }
  bool IsPreIndex() const {
    return addrmode_ == PreIndex;
  }
  bool IsPostIndex() const {
    return addrmode_ == PostIndex;
  }

private:
  Register base_;
  Register regoffset_;
  int64_t offset_;
  AddrMode addrmode_;
  Shift shift_;
  Extend extend_;
  int32_t shift_extend_imm_;
};

class Assembler : public AssemblerBase {

public:
  Assembler();

  void CommitRealize(void *address) {
  }

  Code *GetCode() {
    return NULL;
  }

  void FlushICache();

  void Emit(int32_t value);

  void EmitInt64(uint64_t value);

  void bind(Label *label);

  void b(int64_t imm) {
    int32_t imm26 = imm >> 2;
  }

  void add(const Register &rd, const Register &rn, int64_t imm) {
  }
  void sub(const Register &rd, const Register &rn, int64_t imm) {
  }

  void b(Label *label) {
    int offset = LinkAndGetByteOffsetTo(label);
    b(offset);
  }
  void br(Register rn) {
  }

  void mov(const Register &rd, const Register &rm) {
  }

  // load literal
  void ldr(Register rt, int64_t imm) {
    LoadRegLiteralOp op;
    switch (rt.type()) {
    case CPURegister::Register_32:
      op = OPT_W(LDR, literal);
      break;
    case CPURegister::Register_X:
      op = OPT_X(LDR, literal);
      break;
    case CPURegister::SIMD_FP_Register_S:
      op = OPT_S(LDR, literal);
      break;
    case CPURegister::SIMD_FP_Register_D:
      op = OPT_D(LDR, literal);
      break;
    case CPURegister::SIMD_FP_Register_Q:
      op = OPT_Q(LDR, literal);
      break;
    default:
      break;
    }
    EmitLoadRegLiteral(op, rt, imm);
  }

  void ldr(const CPURegister &rt, const MemOperand &src) {
    LoadStoreUnscaledOffsetOp op = OP_X(LDR);
    LoadStoreReg(op, rt, src);
  }

  void str(const CPURegister &rt, const MemOperand &src) {
    LoadStoreUnscaledOffsetOp op = OP_X(STR);
    LoadStoreReg(op, rt, src);
  }

  void ldp(const Register &rt, const Register &rt2, const MemOperand &src) {
    LoadStorePair(OPT_X(LDP, pair), rt, rt2, src);
  }

  void stp(const Register &rt, const Register &rt2, const MemOperand &dst) {
    LoadStorePair(OPT_X(STP, pair), rt, rt2, dst);
  }

  // Move and keep.
  void movk(const Register &rd, uint64_t imm, int shift = -1) {
    MoveWide(rd, imm, shift, MOVK);
  }

  // Move with non-zero.
  void movn(const Register &rd, uint64_t imm, int shift = -1) {
    MoveWide(rd, imm, shift, MOVN);
  }

  // Move with zero.
  void movz(const Register &rd, uint64_t imm, int shift = -1) {
    MoveWide(rd, imm, shift, MOVZ);
  }

private:
  // label helpers.

  static constexpr int kStartOfLabelLinkChain = 0;

  int LinkAndGetByteOffsetTo(Label *label);

  // load helpers.

  void EmitLoadRegLiteral(LoadRegLiteralOp op, CPURegister rt, int64_t imm) {
    const int32_t encoding = op | LFT(imm, 26, 5) | Rt(rt);
    Emit(encoding);
  }

  void LoadStoreReg(LoadStoreUnscaledOffsetOp op, CPURegister rt, const MemOperand &addr) {
    int64_t imm12          = addr.offset();
    const int32_t encoding = op | LFT(imm12, 12, 10) | Rt(addr.regoffset()) | Rt(rt);
    Emit(encoding);
  }

  void MoveWide(Register rd, uint64_t imm, int shift, MoveWideImmediateOp mov_op) {
    assert(shift >= 0);
    shift /= 16;

    XCHECK(imm <= 0xffff);

    int32_t op    = MoveWideImmediateFixed | mov_op;
    int32_t imm16 = LFT(imm, 16, 5);
    Emit(op | sf(rd) | hw(shift) | imm16 | Rd(rd));
  }

  void LoadStorePair(LoadStorePairOffsetOp op, CPURegister rt, CPURegister rt2, const MemOperand &addr) {
    int scale     = bits(op, 30, 31);
    int32_t imm7  = addr.offset() >> scale;
    int32_t memop = op | imm7 | Rt2(rt2) | Rn(addr.regoffset()) | Rt(rt);

    int32_t addrmodeop;
    if (addr.IsPreIndex()) {
      addrmodeop = 0;
    } else {
      addrmodeop = 0;
    }
    Emit(addrmodeop | memop);
  }
}; // namespace arm64

class TurboAssembler : public Assembler {
private:
  // std::vector<PseudoLabel *> pseudo_labels;

public:
  TurboAssembler(Assembler &assembler) {
    assembler_ = assembler;
  }

  void CommitRealize(void *address) {
  }

  Code *GetCode() {
    return NULL;
  }

  void Ldr(Register rt, PseudoLabel *label) {
    const int64_t dest = label->pos() - buffer_.Size();

    if (label->is_bound()) {
      ldr(rt, dest);
    } else {
      ldr(rt, label->pos());
      label->link_to(buffer_.Size());
    }
  }

  void PseudoBind(PseudoLabel *label) {
    const uintptr_t bound_pc = buffer_.Size();
    // If some instructions have been wrote, before the label bound, we need link these `confused` instructions
    if (label->has_confused_instructions()) {
      label->link_confused_instructions();
    }
    label->bind_to(bound_pc);
  }

  void Mov(Register rd, uint64_t imm) {
    const uint32_t w0 = Low32Bits(imm);
    const uint32_t w1 = High32Bits(imm);
    const uint16_t h0 = Low16Bits(w0);
    const uint16_t h1 = High16Bits(w0);
    const uint16_t h2 = Low16Bits(w1);
    const uint16_t h3 = High16Bits(w1);
    movz(rd, h0, 0);
    movk(rd, h1, 16);
    movk(rd, 32);
    movk(rd, h3, 48);
  }

private:
  Assembler assembler_;
};

} // namespace arm64
} // namespace zz

#endif