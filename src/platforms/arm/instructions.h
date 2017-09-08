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

#ifndef platforms_arm_instructions_h
#define platforms_arm_instructions_h

#include "capstone.h"
#include "hookzz.h"

typedef struct _Instruction {
    zpointer address;
    cs_insn *ins_cs;
    uint8_t size;
    zbyte bytes[16];
} Instruction;

#endif