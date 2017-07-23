/**
 *    Copyright 2017 jmpews
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#ifndef platforms_x86_relocator_h
#define platforms_x86_relocator_h

#include "../../zzdeps/zz.h"
#include "../../../include/hookzz.h"

#include "instructions.h"
#include "capstone.h"
#include "writer.h"
#include "reader.h"

bool branch_is_unconditional(Instruction *ins);

Instruction *relocator_read_one(zpointer address, ZZWriter *backup_writer, ZZWriter *relocate_writer);

void relocator_build_invoke_trampoline(zpointer target_addr, ZZWriter *backup_writer, ZZWriter *relocate_writer);

bool relocator_rewrite_ldr(Instruction *ins, ZZWriter *relocate_writer);

bool relocator_rewrite_b(Instruction *ins, ZZWriter *relocate_writer);

bool relocator_rewrite_bl(Instruction *ins, ZZWriter *relocate_writer);

bool relocator_rewrite_b_cond(Instruction *ins, ZZWriter *relocate_writer);

#endif