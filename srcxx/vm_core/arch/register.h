#ifndef ZZ_ARCH_REGISTER_H_
#define ZZ_ARCH_REGISTER_H_

template <typename SubType> class RegisterBase {
public:
  template <int code> static constexpr SubType from_code() {
    return SubType{code};
  }

  static SubType from_code(int code) {
    return SubType{code};
  }

  static constexpr SubType no_reg() {
    return SubType{0};
  }

protected:
  explicit constexpr RegisterBase(int code) : reg_code_(code) {
  }

  int reg_code_;
};

#endif
