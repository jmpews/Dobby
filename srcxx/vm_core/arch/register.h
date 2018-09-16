#ifndef ZZ_ARCH_REGISTER_H_
#define ZZ_ARCH_REGISTER_H_

template <typename SubType> class RegisterBase {
public:
  static SubType from_code(int code) {
    return SubType{code};
  }

protected:
  explicit constexpr RegisterBase(int code) : reg_code_(code) {
  }

  int reg_code_;
};

#endif