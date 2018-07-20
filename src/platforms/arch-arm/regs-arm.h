//    Copyright 2017 jmpews
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

#ifndef platforms_arch_arm_regs_h
#define platforms_arch_arm_regs_h

#include "hookzz.h"
#include "zkit.h"

#include "CommonKit/log/log_kit.h"

#include "instructions.h"

// REF:
// ARM Architecture Reference Manual
// A2.4 Registers

typedef enum _ZzReg {
  ARM_REG_R0 = 0,
  ARM_REG_R1,
  ARM_REG_R2,
  ARM_REG_R3,
  ARM_REG_R4,
  ARM_REG_R5,
  ARM_REG_R6,
  ARM_REG_R7,
  ARM_REG_R8,
  ARM_REG_R9,
  ARM_REG_R10,
  ARM_REG_R11,
  ARM_REG_R12,
  ARM_REG_R13,
  ARM_REG_R14,
  ARM_REG_R15,
  ARM_REG_SP = ARM_REG_R13,
  ARM_REG_LR = ARM_REG_R14,
  ARM_REG_PC = ARM_REG_R15
} ARMReg;

typedef struct _ARMRegInfo {
  int index;
  int meta;
  int width;
} ARMRegInfo;

void arm_register_describe(ARMReg reg, ARMRegInfo *ri);

#endif