#ifndef ARCH_ARM_REGISTERS
#define ARCH_ARM_REGISTERS

#include "core/arch/arm/constants-arm.h"
#include "core/arch/Cpu.h"
#include <set>

namespace zz {
namespace arm {

#define GENERAL_REGISTERS(V)                                                                                           \
  V(r0) V(r1) V(r2) V(r3) V(r4) V(r5) V(r6) V(r7) V(r8) V(r9) V(r10) V(r11) V(r12) V(sp) V(lr) V(pc)

enum RegisterCode {
#define REGISTER_CODE(R) kRegCode_##R,
  GENERAL_REGISTERS(REGISTER_CODE)
#undef REGISTER_CODE
      kRegAfterLast
};

class Register : public RegisterBase {
public:
  explicit constexpr Register(int code) : RegisterBase(code) {
  }

  static constexpr Register Create(int code) {
    return Register(code);
  }

  static constexpr Register R(int code) {
    return Register(code);
  }

  bool Is(const Register &reg) const {
    return (reg.reg_code_ == this->reg_code_);
  }

  bool IsValid() const {
    return (reg_code_ != 0);
  }

  int code() const {
    return reg_code_;
  }

private:
};

typedef Register CPURegister;

#define DECLARE_REGISTER(R) constexpr Register R = Register::Create(kRegCode_##R);
GENERAL_REGISTERS(DECLARE_REGISTER)
#undef DECLARE_REGISTER

constexpr Register no_reg = Register::Create(0);

class RegisterList {
public:
  RegisterList(Register r) {
    add(r);
  }

  void add(Register r) {
    int code = r.code();
    this->regs.insert(code);
  };

  void remove(Register r) {
    int code = r.code();
    this->regs.erase(code);
  }

  void clear() {
    this->regs.clear();
  }

  uint32_t get_code() {
    uint32_t code = 0;
    if (this->regs.size() > 1) {
      for (std::set<uint32_t>::iterator it = this->regs.begin(); it != this->regs.end(); ++it) {
        code |= 0x01 << *it;
      }
    } else {
      code = 0x0004 | *this->regs.begin() << 12;
    }
    return code;
  }

  int size() {
    return this->regs.size();
  }

protected:
  std::set<uint32_t> regs;
};
} // namespace arm
} // namespace zz
#endif