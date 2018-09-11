#ifndef ZZ_ARCH_ARM64_REGISTERS
#define ZZ_ARCH_ARM64_REGISTERS

#include "vm_core/arch/arm64/constants-arm64.h"
#include "vm_core/macros.h"

namespace zz {
namespace arm64 {

class CPURegister {
public:
  enum RegisterType {
    Register_32,
    Register_W = Register_32,
    Register_64,
    Register_X = Register_64,

    SIMD_FP_Register_8,
    SIMD_FP_Register_B = SIMD_FP_Register_8,
    SIMD_FP_Register_16,
    SIMD_FP_Register_H = SIMD_FP_Register_16,
    SIMD_FP_Register_32,
    SIMD_FP_Register_S = SIMD_FP_Register_32,
    SIMD_FP_Register_64,
    SIMD_FP_Register_D = SIMD_FP_Register_64,
    SIMD_FP_Register_128,
    SIMD_FP_Register_Q = SIMD_FP_Register_128,
    Invalid
  };

  constexpr CPURegister(int code, int size, RegisterType type) : reg_code_(code), reg_size_(size), reg_type_(type) {
  }

  static constexpr CPURegister Create(int code, int size, RegisterType type) {
    return CPURegister(code, size, type);
  }

  static constexpr CPURegister X(int code) {
    return CPURegister(code, 64, Register_64);
  }

  static constexpr CPURegister W(int code) {
    return CPURegister(code, 32, Register_32);
  }

  static constexpr CPURegister Q(int code) {
    return CPURegister(code, 128, SIMD_FP_Register_128);
  }

  static constexpr CPURegister SP() {
    return CPURegister(63, 64, Register_64);
  }

  static constexpr CPURegister None() {
    return CPURegister(0, 0, Invalid);
  }

  bool Is64Bits() const {
    return reg_size_ == 64;
  }

  RegisterType type() const {
    return reg_type_;
  }

  int32_t code() const {
    return reg_code_;
  };

private:
  RegisterType reg_type_;
  int reg_code_;
  int reg_size_;
};

typedef CPURegister Register;
typedef CPURegister VRegister;

// clang-format off
#define GENERAL_REGISTER_CODE_LIST(R)                     \
  R(0)  R(1)  R(2)  R(3)  R(4)  R(5)  R(6)  R(7)          \
  R(8)  R(9)  R(10) R(11) R(12) R(13) R(14) R(15)         \
  R(16) R(17) R(18) R(19) R(20) R(21) R(22) R(23)         \
  R(24) R(25) R(26) R(27) R(28) R(29) R(30) R(31)

#define DEFINE_REGISTER(register_class, name, ...) constexpr register_class name = register_class::Create(__VA_ARGS__)

#define DEFINE_REGISTERS(N)                                                                                            \
  DEFINE_REGISTER(Register, w##N, N, 32, CPURegister::Register_32);                                                                 \
  DEFINE_REGISTER(Register, x##N, N, 64, CPURegister::Register_64);
    GENERAL_REGISTER_CODE_LIST(DEFINE_REGISTERS)
#undef DEFINE_REGISTERS

#define DEFINE_VREGISTERS(N)                                                                                           \
  DEFINE_REGISTER(VRegister, b##N, N, 8, CPURegister::SIMD_FP_Register_8);                                                                \
  DEFINE_REGISTER(VRegister, h##N, N, 16, CPURegister::SIMD_FP_Register_16);                                                                \
  DEFINE_REGISTER(VRegister, s##N, N, 32, CPURegister::SIMD_FP_Register_32);                                                                \
  DEFINE_REGISTER(VRegister, d##N, N, 64, CPURegister::SIMD_FP_Register_64);                                                                \
  DEFINE_REGISTER(VRegister, q##N, N, 128, CPURegister::SIMD_FP_Register_128);                                                                \
GENERAL_REGISTER_CODE_LIST(DEFINE_VREGISTERS)
#undef DEFINE_VREGISTERS

#undef DEFINE_REGISTER
// clang-format on

} // namespace arm64
} // namespace zz

#define X(code) CPURegister::X(code)
#define Q(code) CPURegister::Q(code)
#define SP CPURegister::SP()
#define InvalidRegister CPURegister::None()

#endif
