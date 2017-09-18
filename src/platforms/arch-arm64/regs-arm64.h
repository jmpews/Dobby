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

#include "hookzz.h"

// TODO:
typedef enum _ZzReg {
    //   zzfp = 29,
    //   zzlr = 30,
    //   zzsp = 31,
            zzx0 = 0,
    zzx1,
    zzx2,
    zzx3,
    zzx4,
    zzx5,
    zzx6,
    zzx7,
    zzx8,
    zzx9,
    zzx10,
    zzx11,
    zzx12,
    zzx13,
    zzx14,
    zzx15,
    zzx16,
    zzx17,
    zzx18,
    zzx19,
    zzx20,
    zzx21,
    zzx22,
    zzx23,
    zzx24,
    zzx25,
    zzx26,
    zzx27,
    zzx28,
    zzx29,
    zzx30,
    zzx31,
    zzfp = zzx29,
    zzlr = zzx30,
    zzsp = zzx31
} ZzReg;

typedef struct _ZzArm64RegInfo {
    zuint index;
    zuint meta;
    zuint width;
    zbool is_integer;
} ZzArm64RegInfo;

void zz_arm64_register_describe(arm64_reg reg, ZzArm64RegInfo *ri);