#ifndef CORE_ARCH_CPU_REGISTER_H_
#define CORE_ARCH_CPU_REGISTER_H_

class Register;

class RegisterBase {
public:
  static constexpr RegisterBase from_code(int code);

  static constexpr RegisterBase no_reg();

protected:
  explicit constexpr RegisterBase(int code) : reg_code_(code) {}

  int reg_code_;
};

#endif
