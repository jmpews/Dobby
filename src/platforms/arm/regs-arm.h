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
    zzr14
}

typedef struct _ZzArmRegInfo {
    zuint index;
    zuint meta;
    zuint width;
} ZzArmRegInfo;