//
// Created by jmpews on 2018/6/14.
//

#include "ARM64Register.h"

void DescribeARM64Reigster(ARM64Reg reg, ARM64RegInfo *ri) {
  if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
    ri->isInteger = true;
    ri->width     = 64;
    ri->meta      = ARM64_REG_X0 + (reg - ARM64_REG_X0);
  } else if (reg == ARM64_REG_X29 || reg == ARM64_REG_FP) {
    ri->isInteger = true;
    ri->width     = 64;
    ri->meta      = ARM64_REG_X29;
  } else if (reg == ARM64_REG_X30 || reg == ARM64_REG_LR) {
    ri->isInteger = true;
    ri->width     = 64;
    ri->meta      = ARM64_REG_X30;
  } else if (reg == ARM64_REG_SP) {
    ri->isInteger = true;
    ri->width     = 64;
    ri->meta      = ARM64_REG_X31;
  } else {
    ri->index = 0;
    // LOG-NEED
  }
  ri->index = ri->meta - ARM64_REG_X0;
}

ARM64Reg DisDescribeARM64Reigster(int regIndex, int regWith) {
  if (regWith == 0)
    regWith = 64;

  return (ARM64Reg)(regIndex - (int)ARM64_REG_X0);
}