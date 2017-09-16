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

#ifndef platforms_arch_arm64_relocator_h
#define platforms_arch_arm64_relocator_h

#include "capstone.h"

#include "hookzz.h"

#include "instructions.h"
#include "writer-arm64.h"
#include "reader.h"
#include "relocator.h"


zboolbranch_is_unconditional(Instruction *ins);

Instruction *relocator_read_one(zpointer address, ZzWriter *backup_writer, ZzWriter *relocate_writer);

zboolrelocator_rewrite_ldr(Instruction *ins, ZzWriter *relocate_writer);

zboolrelocator_rewrite_b(Instruction *ins, ZzWriter *relocate_writer);

zboolrelocator_rewrite_bl(Instruction *ins, ZzWriter *relocate_writer);

zboolrelocator_rewrite_adr(Instruction *ins, ZzWriter *relocate_writer);

zboolrelocator_rewrite_b_cond(Instruction *ins, ZzWriter *relocate_writer);

#endif