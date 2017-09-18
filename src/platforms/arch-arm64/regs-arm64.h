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

#ifndef platforms_arch_arm64_regs_h
#define platforms_arch_arm64_regs_h

// platforms
#include "instructions.h"

// hookzz

// zzdeps
#include "hookzz.h"
#include "zzdefs.h"
#include "zzdeps/common/debugbreak.h"
#include "zzdeps/zz.h"

typedef enum _ZzReg {
    ZZ_ARM64_X0 = 0,
    ZZ_ARM64_X1,
    ZZ_ARM64_X2,
    ZZ_ARM64_X3,
    ZZ_ARM64_X4,
    ZZ_ARM64_X5,
    ZZ_ARM64_X6,
    ZZ_ARM64_X7,
    ZZ_ARM64_X8,
    ZZ_ARM64_X9,
    ZZ_ARM64_X10,
    ZZ_ARM64_X11,
    ZZ_ARM64_X12,
    ZZ_ARM64_X13,
    ZZ_ARM64_X14,
    ZZ_ARM64_X15,
    ZZ_ARM64_X16,
    ZZ_ARM64_X17,
    ZZ_ARM64_X18,
    ZZ_ARM64_X19,
    ZZ_ARM64_X20,
    ZZ_ARM64_X21,
    ZZ_ARM64_X22,
    ZZ_ARM64_X23,
    ZZ_ARM64_X24,
    ZZ_ARM64_X25,
    ZZ_ARM64_X26,
    ZZ_ARM64_X27,
    ZZ_ARM64_X28,
    ZZ_ARM64_X29,
    ZZ_ARM64_X30,
    ZZ_ARM64_X31,
    ZZ_ARM64_FP = ZZ_ARM64_X29,
    ZZ_ARM64_LR = ZZ_ARM64_X30,
    ZZ_ARM64_SP = ZZ_ARM64_X31
} ZzReg;

typedef struct _ZzArm64RegInfo {
    zuint index;
    zuint meta;
    zuint width;
    zbool is_integer;
} ZzArm64RegInfo;

void zz_arm64_register_describe(arm64_reg reg, ZzArm64RegInfo *ri);

#endif