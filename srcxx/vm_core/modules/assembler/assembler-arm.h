#ifndef ZZ_ARCH_ARM_ASSEMBLER_H_
#define ZZ_ARCH_ARM_ASSEMBLER_H_

#include "vm_core/arch/arm/constants-arm.h"
#include "vm_core/arch/arm/registers-arm.h"

#include "vm_core/modules/assembler/assembler.h"

#include "vm_core/base/code-buffer.h"
#include "vm_core/macros.h"
#include "vm_core/utils.h"

#include <assert.h>

namespace zz {
namespace arm {

constexpr Register TMP0 = r12;

class Operand {
public:
  explicit Operand(int immediate) : immediate_(immediate), rm_(no_reg), rs_(no_reg) {

    // ===
    assert(immediate < (1 << kImmed8Bits));
    type_     = 1;
    encoding_ = immediate;
  }
  explicit Operand(Register rm) : immediate_(-1), rm_(rm), rs_(no_reg) {

    // ===
    type_     = 0;
    encoding_ = static_cast<uint32_t>(rm.code());
  }
  explicit Operand(Register rm, Shift shift, int shift_imm)
      : immediate_(-1), rm_(rm), rs_(no_reg), shift_(shift), shift_imm_(shift & 31) {
    UNREACHABLE();

    // ===
    assert(shift_imm < (1 << kShiftImmBits));
    type_ = 0;
    encoding_ =
        shift_imm << kShiftImmShift | static_cast<uint32_t>(shift) << kShiftShift | static_cast<uint32_t>(rm.code());
  }
  explicit Operand(Register rm, Shift shift, Register rs) : immediate_(-1), rm_(rm), rs_(rs), shift_(shift) {
    UNREACHABLE();

    // ===
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

  // ===
  uint32_t type_; // Encodes the type field (bits 27-25) in the instruction.
  uint32_t encoding_;

  // ===
  friend class OpEncode;
};

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

private:
  Register rn_;    // base
  Register rm_;    // register offset
  int32_t offset_; // valid if rm_ == no_reg
  Shift shift_;
  int shift_imm_; // valid if rm_ != no_reg && rs_ == no_reg
  AddrMode am_;   // bits P, U, and W

  // =====
  friend class OpEncode;
};

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
    uint32_t encoding;
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

  // ===
  static inline uint32_t Operand(const Operand o) {
    uint32_t encoding;

    // Immeidate
    if (o.rm_.code() == no_reg.code()) {
      encoding |= o.immediate_;
      encoding |= B25;
    } else if (o.rm_.code() != no_reg.code()) {
      encoding = static_cast<uint32_t>(o.rm_.code());
    } else {
      UNREACHABLE();
    }
    return encoding;
  }
};

class Assembler : public AssemblerBase {
public:
  void Emit(int32_t value) {
    buffer_.Emit(value);
  }

  // ===
  void sub(Register dst, Register src1, const Operand &src2, Condition cond = AL) {
    EmitType01(cond, SUB, 0, dst, src1, src2);
  }
  void add(Register dst, Register src1, const Operand &src2, Condition cond = AL) {
    EmitType01(cond, ADD, 0, dst, src1, src2);
  }

  // =====

  void ldr(Register dst, const MemOperand &src, Condition cond = AL) {
    EmitMemOp(cond, true, false, dst, src);
  }
  void str(Register src, const MemOperand &dst, Condition cond = AL) {
    EmitMemOp(cond, false, false, src, dst);
  }

  // =====

  void mov(Register dst, const Operand &src, Condition cond = AL) {
    EmitType01(cond, MOV, 0, dst, no_reg, src);
  }
  void mov(Register dst, Register src, Condition cond = AL) {
  }

  // =====

  // Branch instructions.
  void b(int branch_offset, Condition cond = AL) {
    EmitType5(cond, branch_offset, false);
  }
  void bl(int branch_offset, Condition cond = AL) {
  }
  void blx(int branch_offset) {
  }
  void blx(Register target, Condition cond = AL) {
  }
  void bx(Register target, Condition cond = AL) {
  }

private:
  void EmitType01(Condition cond, Opcode opcode, int set_cc, Register rd, Register rn, Operand o) {
    ASSERT(rd != no_reg);
    ASSERT(cond != kNoCondition);

    int32_t encoding = static_cast<int32_t>(cond) << kConditionShift | static_cast<int32_t>(opcode) << kOpcodeShift |
                       set_cc << kSShift | OpEncode::Rn(rn) | OpEncode::Rd(rd) | OpEncode::Operand(o);
    Emit(encoding);
  }
  void EmitType5(Condition cond, int32_t offset, bool link) {
    ASSERT(cond != kNoCondition);
    int32_t encoding = static_cast<int32_t>(cond) << kConditionShift | LFT(5, 3, 25) | (link ? 1 : 0) << kLinkShift;
    Emit(offset | encoding);
  }
  void EmitMemOp(Condition cond, bool load, bool byte, Register rd, const MemOperand x) {
    ASSERT(rd != no_reg);
    ASSERT(cond != kNoCondition);

    int32_t encoding =
        (static_cast<int32_t>(cond) << kConditionShift) | B26 | (load ? L : 0) | (byte ? B : 0) | OpEncode::Rd(rd);
    Emit(encoding);
  }
};

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
    // trick: use bl to replace lr register
    bl(0);
    b(4);
    ldr(pc, MemOperand(pc, -4));
    Emit((uint32_t)function.address());
  }

  // =====

  void Move32Immeidate(Register rd, const Operand &x, Condition cond = AL) {
  }

private:
  void *released_address_;
};

} // namespace arm
} // namespace zz

#endif