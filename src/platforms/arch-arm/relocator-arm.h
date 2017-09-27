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

#ifndef platforms_arch_arm_relocator_arm_h
#define platforms_arch_arm_relocator_arm_h

// platforms
#include "instructions.h"
#include "regs-arm.h"
#include "writer-arm.h"

// hookzz
#include "writer.h"

// zzdeps
#include "hookzz.h"
#include "zzdefs.h"
#include "zzdeps/common/debugbreak.h"
#include "zzdeps/zz.h"

typedef struct _ZzArmRelocator {
    csh capstone;

    zpointer input_start;
    zpointer input_cur;
    zaddr input_pc;
    ZzInstruction *input_insns;
    ZzArmWriter *output;

    zuint inpos;
    zuint outpos;
} ZzArmRelocator;

void zz_arm_relocator_init(ZzArmRelocator *relocator, zpointer input_code, ZzArmWriter *writer);
void zz_arm_relocator_reset(ZzArmRelocator *relocator, zpointer input_code, ZzArmWriter *writer);
zsize zz_arm_relocator_read_one(ZzArmRelocator *self, ZzInstruction *instruction);
zbool zz_arm_relocator_write_one(ZzArmRelocator *self);
void zz_arm_relocator_write_all(ZzArmRelocator *self);
void zz_arm_relocator_try_relocate(zpointer address, zuint min_bytes, zuint *max_bytes);

static zbool zz_arm_branch_is_unconditional(const cs_insn *insn_ctx);
static zbool zz_arm_relocator_rewrite_ldr(ZzArmRelocator *self, ZzInstruction *insn_ctx);
static zbool zz_arm_relocator_rewrite_add(ZzArmRelocator *self, ZzInstruction *insn_ctx);
static zbool zz_arm_relocator_rewrite_b(ZzArmRelocator *self, cs_mode target_mode,
                                        ZzInstruction *insn_ctx);
static zbool zz_arm_relocator_rewrite_bl(ZzArmRelocator *self, cs_mode target_mode,
                                         ZzInstruction *insn_ctx);
#endif