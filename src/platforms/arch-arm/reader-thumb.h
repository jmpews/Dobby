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

#ifndef platforms_arch_arm_reader_thumb_h
#define platforms_arch_arm_reader_thumb_h

#include "instructions.h"

#include "trampoline.h"

#include "zzdeps/common/debugbreak.h"
#include "zzdeps/zz.h"
#include "hookzz.h"

cs_insn *zz_thumb_reader_disassemble_at(zpointer address);

#endif