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

constexpr Register TMP0 = x17;
constexpr Register TMP1 = x16;

#define Rd(rd) (rd.code() << kRdShift)
#define Rt(rt) (rt.code() << kRtShift)
#define Rt2(rt) (rt.code() << kRt2Shift)
#define Rn(rn) (rn.code() << kRnShift)
#define Rm(rm) (rm.code() << kRmShift)

class PseudoLabel : public Label {
public:
  enum PseudoLabelType { kLdrLiteralPseudoLabel };

  typedef struct _PseudoLabelInstruction {
    int position_;
    PseudoLabelType type_;
  } PseudoLabelInstruction;

  bool has_confused_instructions() {
    return instructions_.size() > 0;
  }

  void link_confused_instructions(CodeBuffer *buffer = nullptr) {
    CodeBuffer *_buffer;
    if (buffer)
      _buffer = buffer;

    for (auto instruction : instructions_) {
      int32_t offset       = pos() - instruction.position_;
      const int32_t inst32 = _buffer->Load32(instruction.position_);
      int32_t encoded      = 0;

      switch (instruction.type_) {
      case kLdrLiteralPseudoLabel: {
        encoded = inst32 & 0xFF00001F;
        encoded = encoded | LFT((offset >> 2), 19, 5);
      } break;
      default:
        UNREACHABLE();
        break;
      }
      _buffer->Store32(instruction.position_, encoded);
    }
  };

  void link_to(int pos, PseudoLabelType type) {
    instructions_.push_back({pos, type});
  }

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
  inline explicit Operand(int64_t imm)
      : immediate_(imm), reg_(InvalidRegister), shift_(NO_SHIFT), extend_(NO_EXTEND), shift_extent_imm_(0) {
  }
  inline Operand(Register reg, Shift shift = LSL, int32_t imm = 0)
      : immediate_(0), reg_(reg), shift_(shift), extend_(NO_EXTEND), shift_extent_imm_(imm) {
  }
  inline Operand(Register reg, Extend extend, int32_t imm = 0)
      : immediate_(0), reg_(reg), shift_(NO_SHIFT), extend_(extend), shift_extent_imm_(imm) {
  }

  // =====

  bool IsImmediate() const {
    return reg_.Is(InvalidRegister) && immediate_ != 0;
  }
  bool IsShiftedRegister() const {
    return /* reg_.IsValid() && */ (shift_ != NO_SHIFT);
  }
  bool IsExtendedRegister() const {
    return /* reg_.IsValid() && */ (extend_ != NO_EXTEND);
  }

  // =====

  Register reg() const {
    DCHECK(IsShiftedRegister() || IsExtendedRegister());
    return reg_;
  }
  int64_t Immediate() const {
    return immediate_;
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

  // =====

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

  // =====

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

class OpEncode {

public:
  static int32_t sf(const Register &reg, int32_t op) {
    return (op | sf(reg));
  }

  static int32_t sf(const Register &reg) {
    if (reg.Is64Bits())
      return LFT(1, 1, 31);
    return 0;
  }

  static int32_t V(const Register &reg, int32_t op) {
    return (op | V(reg));
  }

  static int32_t V(const Register &reg) {
    if (reg.IsVRegister())
      return LFT(1, 1, 26);
    return 0;
  }

  static int32_t shift(Shift shift) {
    return LFT(shift, 2, 22);
  }

  static int32_t EncodeLogicalImmediate(const Register &rd, const Register &rn, const Operand &operand) {
    int64_t imm = operand.Immediate();
    int32_t N, imms, immr;
    immr = bits(imm, 0, 5);
    imms = bits(imm, 6, 11);
    N    = bit(imm, 12);

    return (sf(rd) | LFT(immr, 6, 16) | LFT(imms, 6, 10) | Rd(rd) | Rn(rn));
  }

  static int32_t EncodeLogicalShift(const Register &rd, const Register &rn, const Operand &operand) {
    return (sf(rd) | shift(operand.shift()) | Rm(operand.reg()) | LFT(operand.shift_extend_imm(), 6, 10) | Rn(rn) |
            Rd(rd));
  }
};

class Assembler : public AssemblerBase {

public:
  Assembler();

  void CommitRealize(void *address) {
  }

  Code *GetCode() {
  }

  void FlushICache();

  // =====

  void Emit(int32_t value);

  void EmitInt64(uint64_t value);

  // =====

  void bind(Label *label);

  // =====

  void add(const Register &rd, const Register &rn, int64_t imm) {
    if (rd.Is64Bits() && rn.Is64Bits())
      AddSubImmediate(rd, rn, Operand(imm), OPT_X(ADD, imm));
    else
      AddSubImmediate(rd, rn, Operand(imm), OPT_W(ADD, imm));
  }
  void adds(const Register &rd, const Register &rn, int64_t imm) {
    UNREACHABLE();
  }
  void sub(const Register &rd, const Register &rn, int64_t imm) {
    if (rd.Is64Bits() && rn.Is64Bits())
      AddSubImmediate(rd, rn, Operand(imm), OPT_X(SUB, imm));
    else
      AddSubImmediate(rd, rn, Operand(imm), OPT_W(SUB, imm));
  }
  void subs(const Register &rd, const Register &rn, int64_t imm) {
    UNREACHABLE();
  }

  // =====

  void b(int64_t imm) {
    int32_t imm26 = imm >> 2;
    Emit(B | imm26);
  }
  void b(Label *label) {
    int offset = LinkAndGetByteOffsetTo(label);
    b(offset);
  }
  void br(Register rn) {
    Emit(BR | Rn(rn));
  }
  void blr(Register rn) {
    Emit(BLR | Rn(rn));
  }

  // =====

  void ldr(Register rt, int64_t imm) {
    LoadRegLiteralOp op;
    switch (rt.type()) {
    case CPURegister::kRegister_32:
      op = OPT_W(LDR, literal);
      break;
    case CPURegister::kRegister_X:
      op = OPT_X(LDR, literal);
      break;
    case CPURegister::kSIMD_FP_Register_S:
      op = OPT_S(LDR, literal);
      break;
    case CPURegister::kSIMD_FP_Register_D:
      op = OPT_D(LDR, literal);
      break;
    case CPURegister::kSIMD_FP_Register_Q:
      op = OPT_Q(LDR, literal);
      break;
    default:
      UNREACHABLE();
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

  // =====

  void mov(const Register &rd, const Register &rn) {
    if ((rd.Is(SP)) || (rn.Is(SP))) {
      add(rd, rn, 0);
    } else {
      if (rd.Is64Bits())
        orr(rd, xzr, Operand(rn));
      else
        orr(rd, wzr, Operand(rn));
    }
  }
  void movk(const Register &rd, uint64_t imm, int shift = -1) {
    // Move and keep.
    MoveWide(rd, imm, shift, MOVK);
  }
  void movn(const Register &rd, uint64_t imm, int shift = -1) {
    // Move with non-zero.
    MoveWide(rd, imm, shift, MOVN);
  }
  void movz(const Register &rd, uint64_t imm, int shift = -1) {
    // Move with zero.
    MoveWide(rd, imm, shift, MOVZ);
  }

  // =====

  void orr(const Register &rd, const Register &rn, const Operand &operand) {
    Logical(rd, rn, operand, ORR);
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

  // =====

  void MoveWide(Register rd, uint64_t imm, int shift, MoveWideImmediateOp op) {
    assert(shift >= 0);
    shift /= 16;

    int32_t imm16 = LFT(imm, 16, 5);
    Emit(MoveWideImmediateFixed | op | OpEncode::sf(rd) | LFT(shift, 2, 21) | imm16 | Rd(rd));
  }

  // =====

  void AddSubImmediate(const Register &rd, const Register &rn, const Operand &operand, AddSubImmediateOp op) {
    if (operand.IsImmediate()) {
      int64_t immediate = operand.Immediate();
      int32_t imm12     = LFT(immediate, 12, 10);
      Emit(op | Rd(rd) | Rn(rn) | imm12);
    } else {
      UNREACHABLE();
    }
  }

  // =====

  void Logical(const Register &rd, const Register &rn, const Operand &operand, LogicalOp op) {
    if (operand.IsImmediate()) {
      LogicalImmediate(rd, rn, operand, op);
    } else {
      LogicalShift(rd, rn, operand, op);
    }
  }
  void LogicalImmediate(const Register &rd, const Register &rn, const Operand &operand, LogicalOp op) {
    int32_t combine_fields_op = OpEncode::EncodeLogicalImmediate(rd, rn, operand);
    Emit(op | combine_fields_op);
  }
  void LogicalShift(const Register &rd, const Register &rn, const Operand &operand, LogicalOp op) {
    int32_t combine_fields_op = OpEncode::EncodeLogicalShift(rd, rn, operand);
    Emit(op | combine_fields_op);
  }

}; // namespace arm64

class TurboAssembler : public Assembler {
public:
  TurboAssembler() {
  }

  void CommitRealize(void *address) {
    released_address_ = address;
  }

  Code *GetCode() {
    Code *code = new Code(released_address_, CodeSize());
    return code;
  }

  // =====

  void CallFunction(ExternalReference function) {
    Mov(TMP0, (uint64_t)function.address());
    blr(TMP0);
  }

  // =====

  void Ldr(Register rt, PseudoLabel *label) {
    if (label->is_bound()) {
      const int64_t dest = label->pos() - buffer_.Size();
      ldr(rt, dest);
    } else {
      // record this ldr, and fix later.
      label->link_to(buffer_.Size(), PseudoLabel::kLdrLiteralPseudoLabel);
      ldr(rt, 0);
    }
  }

  // =====

  void PseudoBind(PseudoLabel *label) {
    const uintptr_t bound_pc = buffer_.Size();
    label->bind_to(bound_pc);
    // If some instructions have been wrote, before the label bound, we need link these `confused` instructions
    if (label->has_confused_instructions()) {
      label->link_confused_instructions(this->GetCodeBuffer());
    }
  }

  // =====

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

  void *released_address_;
};

} // namespace arm64
} // namespace zz

#endif
