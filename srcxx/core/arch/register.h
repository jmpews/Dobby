#ifndef ARCH_REGISTER_H_
#define ARCH_REGISTER_H_

class RegisterBase {
public:
  static constexpr RegisterBase *from_code(int code) { return RegisterBase(code); }

  static constexpr RegisterBase *no_reg() { return RegisterBase{0}; }

protected:
  explicit constexpr RegisterBase(int code) : reg_code_(code) {}

  int reg_code_;
};

#endif
