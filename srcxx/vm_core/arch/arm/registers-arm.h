#ifndef ARCH_ARM_REGISTERS
#define ARCH_ARM_REGISTERS

#include "vm_core/arch/arm/constants-arm.h"
#include "vm_core/arch/register.h"
#include "vm_core/macros.h"

namespace zz {
namespace arm64 {

#define GENERAL_REGISTERS(V)                                                                                           \
  V(r0) V(r1) V(r2) V(r3) V(r4) V(r5) V(r6) V(r7) V(r8) V(r9) V(r10) V(fp) V(ip) V(sp) V(lr) V(pc)

enum RegisterCode {
#define REGISTER_CODE(R) kRegCode_##R,
  GENERAL_REGISTERS(REGISTER_CODE)
#undef REGISTER_CODE
      kRegAfterLast
};

class Register : public RegisterBase {
public:
  constexpr Register(int code) : reg_code_(code) {
  }
  static constexpr Register Create(int code) {
    return CPURegister(code);
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

// r7: context register
// r9: lithium scratch
#define DECLARE_REGISTER(R) constexpr Register R = Register::from_code<kRegCode_##R>();
GENERAL_REGISTERS(DECLARE_REGISTER)
#undef DECLARE_REGISTER

} // namespace arm64
} // namespace zz
#endif