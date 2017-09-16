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

#include "instructions.h"

#include "zzdeps/common/debugbreak.h"
#include "zzdeps/zz.h"
#include "hookzz.h"
// REF:
// ARM Architecture Reference Manual
// A2.4 Registers

typedef enum _ZzReg {
    zzr0 = 0,
    zzr1,
    zzr2,
    zzr3,
    zzr4,
    zzr5,
    zzr6,
    zzr7,
    zzr8,
    zzr9,
    zzr10,
    zzr11,
    zzr12,
    zzr13,
    zzr14,
    zzr15,
    zzsp = zzr13,
    zzlr = zzr14,
    zzpc = zzr15
} ZzReg;

typedef struct _ZzArmRegInfo {
    zuint index;
    zuint meta;
    zuint width;
} ZzArmRegInfo;

void zz_arm_register_describe(arm_reg reg, ZzArmRegInfo *ri);

void zz_arm_register_describe(arm_reg reg, ZzArmRegInfo *ri) {
    if (reg >= ARM_REG_R0 && reg <= ARM_REG_R12) {
        ri->width = 32;
        ri->meta = zzr0 + (reg - ARM_REG_R0);
    } else if (reg == ARM_REG_R13 || reg == ARM_REG_SP) {
        ri->width = 32;
        ri->meta = zzr13;
    } else if (reg == ARM_REG_R14 || reg == ARM_REG_LR) {
        ri->width = 32;
        ri->meta = zzr14;
    } else if (reg == ARM_REG_PC) {
        ri->width = 32;
        ri->meta = zzr15;
    } else {
        Serror("zz_arm64_register_describe error.");
        #if defined(DEBUG_MODE)
            debug_break();
        #endif
        ri->index = 0;
    }
    ri->index = ri->meta - zzr0;
}

#endif