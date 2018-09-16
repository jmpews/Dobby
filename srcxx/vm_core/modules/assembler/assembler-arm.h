#ifndef ZZ_ARCH_ARM_ASSEMBLER_H_
#define ZZ_ARCH_ARM_ASSEMBLER_H_

#include "vm_core/arch/arm/constants-arm.h"
#include "vm_core/arch/arm/registers-arm.h"

#include "vm_core/modules/assembler/assembler.h"

#include "vm_core/base/code-buffer.h"
#include "vm_core/macros.h"
#include "vm_core/utils.h"

#include <assert.h>

namespace zz {
namespace arm {

constexpr Register TMP0 = r11;
constexpr Register TMP1 = r12;

class Operand {};

class MemOperand {};

class Assembler : public AssemblerBase {
  // =====

  void sub(Register dst, Register src1, const Operand &src2, Condition cond = al) {
  }
  void add(Register dst, Register src1, const Operand &src2, Condition cond = al) {
  }

  // =====

  void ldr(Register dst, const MemOperand &src, Condition cond = al) {
  }
  void str(Register src, const MemOperand &dst, Condition cond = al) {
  }

  // =====

  // Branch instructions.
  void b(int branch_offset, Condition cond = al) {
  }
  void bl(int branch_offset, Condition cond = al) {
  }
  void blx(int branch_offset) {
  }
  void blx(Register target, Condition cond = al) {
  }
  void bx(Register target, Condition cond = al) {
  }
}

} // namespace arm
} // namespace zz
