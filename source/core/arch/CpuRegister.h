#pragma once

struct RegisterBase {
  int reg_id;

  static constexpr RegisterBase from_code(int reg_id) {
    return RegisterBase{reg_id};
  }

  static constexpr RegisterBase no_reg() {
    return RegisterBase{0};
  }

  explicit constexpr RegisterBase(int code) : reg_id(code) {
  }

  bool operator==(const RegisterBase &other) const {
    return reg_id == other.reg_id;
  }

  int code() const {
    return reg_id;
  };
};