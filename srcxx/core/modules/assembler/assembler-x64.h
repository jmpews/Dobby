#ifndef CORE_MODULES_ASSEMBLER_X64_ASSEMBLER_H_
#define CORE_MODULES_ASSEMBLER_X64_ASSEMBLER_H_

#include "core/arch/x64/constants-x64.h"
#include "core/arch/x64/registers-x64.h"

#include "core/modules/assembler/assembler.h"

#include "ExecMemory/CodeBuffer/code-buffer-x64.h"

#include "macros.h"

#include "logging/logging.h"

namespace zz {
namespace x64 {

#define IsInt8(imm) ((2 ^ 8) > imm)

class PseudoLabel : public Label {
public:
};

#define ModRM_Mod(byte) ((byte & 0b11000000) >> 6)
#define ModRM_RegOpcode(byte) ((byte & 0b00111000) >> 3)
#define ModRM_RM(byte) (byte & 0b00000111)

typedef union _ModRM {
  byte ModRM;
  struct {
    byte RM : 3;
    byte RegOpcode : 3;
    byte Mod : 2;
  };
} ModRM;

// ===== Immediate =====

class Immediate {
public:
  explicit Immediate(int64_t imm) : value_(imm) {
  }

  int64_t value() const {
    return value_;
  }

  int value_size() const {
    UNREACHABLE();
    return 0;
  }

private:
  const int64_t value_;
};

// ===== Operand =====

class Operand {
public:
  // [base]
  Operand(Register base);

  // [base + disp/r]
  Operand(Register base, int32_t disp);

  // [base + index*scale + disp/r]
  Operand(Register base, Register index, ScaleFactor scale, int32_t disp);

  // [index*scale + disp/r]
  Operand(Register index, ScaleFactor scale, int32_t disp);

public: // Getter and Setter
  uint8_t rex() const {
    return rex_;
  }

  inline uint8_t rex_b() const {
    return (rex_ & REX_B);
  }

  inline uint8_t rex_x() const {
    return (rex_ & REX_X);
  }

  inline uint8_t rex_r() const {
    return (rex_ & REX_R);
  }

  inline uint8_t rex_w() const {
    return (rex_ & REX_W);
  }

  uint8_t mod() const {
    return (encoding_at(0) >> 6) & 3;
  }

  Register rm() const {
    int rm_rex = rex_b() << 3;
    return Register::from_code(rm_rex + (encoding_at(0) & 7));
  }

  ScaleFactor scale() const {
    return static_cast<ScaleFactor>((encoding_at(1) >> 6) & 3);
  }

  Register index() const {
    int index_rex = rex_x() << 2;
    return Register::from_code(index_rex + ((encoding_at(1) >> 3) & 7));
  }

  Register base() const {
    int base_rex = rex_b() << 3;
    return Register::from_code(base_rex + (encoding_at(1) & 7));
  }

  int8_t disp8() const {
    ASSERT(length_ >= 2);
    return static_cast<int8_t>(encoding_[length_ - 1]);
  }

  int32_t disp32() const {
    ASSERT(length_ >= 5);
    return static_cast<int32_t>(encoding_[length_ - 4]);
  }

protected:
  Operand() : length_(0), rex_(REX_NONE) {
  } // Needed by subclass Address.

  void SetModRM(int mod, Register rm) {
    ASSERT((mod & ~3) == 0);
    if ((rm.code() > 7) && !((rm.Is(r12)) && (mod != 3))) {
      rex_ |= REX_B;
    }
    encoding_[0] = (mod << 6) | (rm.code() & 7);
    length_      = 1;
  }

  void SetSIB(ScaleFactor scale, Register index, Register base) {
    ASSERT(length_ == 1);
    ASSERT((scale & ~3) == 0);
    if (base.code() > 7) {
      ASSERT((rex_ & REX_B) == 0); // Must not have REX.B already set.
      rex_ |= REX_B;
    }
    if (index.code() > 7)
      rex_ |= REX_X;
    encoding_[1] = (scale << 6) | ((index.code() & 7) << 3) | (base.code() & 7);
    length_      = 2;
  }

  void SetDisp8(int8_t disp) {
    ASSERT(length_ == 1 || length_ == 2);
    encoding_[length_++] = static_cast<uint8_t>(disp);
  }

  void SetDisp32(int32_t disp) {
    ASSERT(length_ == 1 || length_ == 2);
    *(int32_t *)&encoding_[length_] = disp;
    length_ += sizeof(disp);
  }

private:
  // explicit Operand(Register reg) : rex_(REX_NONE) { SetModRM(3, reg); }

  // Get the operand encoding byte at the given index.
  uint8_t encoding_at(intptr_t index) const {
    ASSERT(index >= 0 && index < length_);
    return encoding_[index];
  }

public:
  uint8_t length_;
  uint8_t rex_;
  uint8_t encoding_[6];
};

// ===== Address =====

class Address : public Operand {
public:
  Address(Register base, int32_t disp) {
    int base_ = base.code();
    int rbp_  = rbp.code();
    int rsp_  = rsp.code();
    if ((disp == 0) && ((base_ & 7) != rbp_)) {
      SetModRM(0, base);
      if ((base_ & 7) == rsp_) {
        SetSIB(TIMES_1, rsp, base);
      }
    } else if (IsInt8(disp)) {
      SetModRM(1, base);
      if ((base_ & 7) == rsp_) {
        SetSIB(TIMES_1, rsp, base);
      }
      SetDisp8(disp);
    } else {
      SetModRM(2, base);
      if ((base_ & 7) == rsp_) {
        SetSIB(TIMES_1, rsp, base);
      }
      SetDisp32(disp);
    }
  }

  // This addressing mode does not exist.
  Address(Register base, Register r);

  Address(Register index, ScaleFactor scale, int32_t disp) {
    ASSERT(index.code() != rsp.code()); // Illegal addressing mode.
    SetModRM(0, rsp);
    SetSIB(scale, index, rbp);
    SetDisp32(disp);
  }

  // This addressing mode does not exist.
  Address(Register index, ScaleFactor scale, Register r);

  Address(Register base, Register index, ScaleFactor scale, int32_t disp) {
    ASSERT(index.code() != rsp.code()); // Illegal addressing mode.
    int rbp_ = rbp.code();
    if ((disp == 0) && ((base.code() & 7) != rbp_)) {
      SetModRM(0, rsp);
      SetSIB(scale, index, base);
    } else if (IsInt8(disp)) {
      SetModRM(1, rsp);
      SetSIB(scale, index, base);
      SetDisp8(disp);
    } else {
      SetModRM(2, rsp);
      SetSIB(scale, index, base);
      SetDisp32(disp);
    }
  }

  // This addressing mode does not exist.
  Address(Register base, Register index, ScaleFactor scale, Register r);

private:
  Address(Register base, int32_t disp, bool fixed) {
    ASSERT(fixed);
    SetModRM(2, base);
    if ((base.code() & 7) == rsp.code()) {
      SetSIB(TIMES_1, rsp, base);
    }
    SetDisp32(disp);
  }
};

// ===== Assembler =====

class Assembler : public AssemblerBase {
public:
  Assembler(void *address) : AssemblerBase(address) {
    buffer_ = new CodeBuffer(32);
    DLOG("[*] Assembler buffer at %p\n", (CodeBufferBase *)buffer_->getRawBuffer());
  }

  void Emit1(byte val) {
    buffer_->Emit8(val);
  }

  void pushfq() {
    Emit1(0x9C);
  }

  void jmp(Immediate imm);

  // refer android_art
  uint8_t GenREX(bool force, bool w, bool r, bool x, bool b) {
    // REX.WRXB
    // W - 64-bit operand
    // R - MODRM.reg
    // X - SIB.index
    // B - MODRM.rm/SIB.base

    uint8_t rex = force ? 0x40 : 0;
    if (w) {
      rex |= 0x48; // REX.W000
    }
    if (r) {
      rex |= 0x44; // REX.0R00
    }
    if (x) {
      rex |= 0x42; // REX.00X0
    }
    if (b) {
      rex |= 0x41; // REX.000B
    }
    if (rex != 0) {
      return rex;
    }
    return 0;
  }

  void EmitRegisterREX(Register reg) {
    if (reg.size() != 64)
      UNIMPLEMENTED();
    uint8_t rex = GenREX(true, reg.size() == 64, false, false, reg.code() > 7);
    if (!rex)
      Emit1(rex);
  }

  void EmitRegisterOperandREX(Register reg, Operand &operand) {
    if (reg.size() != 64)
      UNIMPLEMENTED();
    uint8_t rex = operand.rex();
    rex |= GenREX(true, reg.size() == 64, false, false, reg.code() > 7);
    if (rex != 0) {
      Emit1(rex);
    }
  }

  void EmitOperandREX(Operand &operand) {
    uint8_t rex = operand.rex();
    rex |= REX_PREFIX;
    if (rex != 0) {
      Emit1(rex);
    }
  }

  void EmitImmediate(Immediate imm, int imm_size) {
    if (imm_size == 8) {
      buffer_->Emit8(imm.value());
    } else if (imm_size == 32) {
      buffer_->Emit32(imm.value());
    }
  }

  inline void EmitModRM(uint8_t Mod, uint8_t RegOpcode, uint8_t RM) {
    uint8_t ModRM = 0;
    ModRM |= Mod << 6;
    ModRM |= RegOpcode << 3;
    ModRM |= RM;
    Emit1(ModRM);
  }

  //  inline void Emit_Mod_Reg_Mem(uint8_t mod, uint8_t reg, uint8_t M) {
  //
  //  }
  //
  //  inline void Emit_Mod_Opcode_Reg(uint8_t extra_opcode, uint8_t reg_code) {
  //    EmitModRM(0b11, extra_opcode, reg_code);
  //  }

  void EmitExtraOpcodeRegister(uint8_t opcode, Register reg) {
    EmitModRM(0b11, opcode, reg.code());
  }

  void EmitRegisterRegister(Register reg1, Register reg2) {
    EmitModRM(0b11, reg1.code(), reg2.code());
  }

  void Emit_OperandEn_Register_Immediate(uint8_t extra_opcode, Register reg, Immediate imm) {
    EmitExtraOpcodeRegister(extra_opcode, reg);
    if(reg.size() == 64)
      EmitImmediate(imm, 32);
    else
      EmitImmediate(imm, reg.size());
  }

  void Emit_OperandEn_Register_Register(Register reg1, Register reg2) {
    EmitRegisterRegister(reg1, reg2);
  }

  void Emit_OperandEn_Register_Operand(Register reg, Operand &operand) {
    ModRM modRM = *(ModRM *)&operand.encoding_[0];
    EmitModRM(modRM.Mod, reg.code(), modRM.RM);
    buffer_->EmitBuffer(&operand.encoding_[1], operand.length_ - 1);
  }

  void Emit_OperandEn_Operand(uint8_t extra_opcode, Operand &operand) {
    ModRM modRM = *(ModRM *)&operand.encoding_[0];
    EmitModRM(modRM.Mod, extra_opcode, modRM.RM);
    buffer_->EmitBuffer(&operand.encoding_[1], operand.length_ - 1);
  }

  void sub(Register reg, Immediate imm) {
    EmitRegisterREX(reg);
    Emit1(0x81);
    Emit_OperandEn_Register_Immediate(0x5, reg, imm);
  }

  void mov(Register dst, Register src) {
    EmitRegisterREX(dst);
    Emit1(0x8B);
    Emit_OperandEn_Register_Register(dst, src);
  }

  void mov(Register dst, Address src) {
    EmitRegisterREX(dst);
    Emit1(0x8B);
    Emit_OperandEn_Register_Operand(dst, src);
  }

  void mov(Address dst, Register src) {
    EmitRegisterOperandREX(src, dst);
    Emit1(0x89);
    Emit_OperandEn_Register_Operand(src, dst);
  }

  void call(Address operand) {
    EmitOperandREX(operand);
    Emit1(0xFF);
    Emit_OperandEn_Operand(0x2, operand);
  }

  void pop(Register reg) {
  }

  void ret() {
  }
};

// ===== TurboAssembler =====

class TurboAssembler : public Assembler {
public:
  TurboAssembler(void *address) : Assembler(address) {
  }

  uint64_t CurrentIP();
};

} // namespace x64
} // namespace zz

#endif
