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

#ifndef reader_h
#define reader_h

#include "../../zzdeps/zz.h"
#include "../../../include/hookzz.h"
#include "instructions.h"

#include "../../trampoline.h"

cs_insn *disassemble_instruction_at(zpointer address);

#define JMP_METHOD_SIZE 16

#endif