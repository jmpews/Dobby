#ifndef ARCH_ARM_REGISTERS
#define ARCH_ARM_REGISTERS

#include "vm_core/arch/arm/constants-arm.h"
#include "vm_core/arch/register.h"
#include "vm_core/macros.h"

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

class Register : public RegisterBase<Register> {
public:
  explicit constexpr Register(int code) : RegisterBase(code) {
  }
  static constexpr Register Create(int code) {
    return Register(code);
  }
  static constexpr Register R(int code) {
    return Register(code);
  }

  // =====

  bool Is(const Register &reg) const {
    return (reg.reg_code_ == this->reg_code_);
  }

  // =====

  int32_t code() const {
    return reg_code_;
  }

private:
};

typedef Register CPURegister;

#define DECLARE_REGISTER(R) constexpr Register R = Register::from_code<kRegCode_##R>();
GENERAL_REGISTERS(DECLARE_REGISTER)
#undef DECLARE_REGISTER

constexpr Register no_reg = Register::no_reg();

} // namespace arm
} // namespace zz
#endif