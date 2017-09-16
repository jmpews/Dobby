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

#include <string.h>
#include "zzdeps/common/debugbreak.h"

#include "relocator-arm.h"
#include "reader-arm.h"
#include "interceptor.h"

typedef struct _ZzArmRelocator {
    csh capstone;
    
    zpointer input_start;
    zpointer input_cur;
    zaddr input_pc;
    Instruction *input_insns;
    ZzWriter *output;

    guint inpos;
    guint outpos;
} ZzArmRelocator;

#define MAX_RELOCATOR_INSTRUCIONS_SIZE 64

zz_arm_relocator_init(ZzArmRelocator *relocator, zpointer input_code, ZzArmWriter *writer) {
    err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle);
    if (err) {
        Xerror("Failed on cs_open() with error returned: %u\n", err);
        exit(-1);
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    relocator->input_start = input_code;
    relocator->input_cur = input_code;
    relocator->input_insns = (Instruction *)malloc(MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(Instruction));
}

void zz_arm_relocator_read_one(ZzArmRelocator *self, Instruction *instruction)
{
    cs_insn ** cs_insn_ptr, * cs_insn;
    Instruction insn = relocator->input_insns[relocator->inspos];
    cs_insn_ptr = &insn.cs_insn

    if (cs_disasm (self->capstone, self->input_cur, 4, self->input_pc, 1,
        cs_insn_ptr) != 1)
    {
      return 0;
    }

    cs_insn = *cs_insn_ptr;

    switch (cs_insn->id)
    {

    }
    
    self->inpos++;

    if (instruction != NULL)
    *instruction = insn;

    self->input_cur += cs_insn->size;
    self->input_pc += cs_insn->size;

    return self->input_cur - self->input_start;
}

zboolbranch_is_unconditional(Instruction *ins)
{
    cs_arm ins_csd = ins->ins_cs->detail->arm;

    switch (ins_csd.cc)
    {
    case ARM64_CC_INVALID:
    case ARM64_CC_AL:
    case ARM64_CC_NV:
        return true;
    default:
        return false;
    }
}

zboolrelocator_rewrite_ldr(Instruction *ins, ZzWriter *relocate_writer)
{
    cs_arm ins_csd = ins->ins_cs->detail->arm;
    const cs_arm_op *dst = &ins_csd.operands[0];
    const cs_arm_op *src = &ins_csd.operands[1];
    if (src->type != ARM64_OP_IMM)
        return false;
    return true;
}

zboolrelocator_rewrite_b(Instruction *ins, ZzWriter *relocate_writer)
{
    cs_arm ins_csd = ins->ins_cs->detail->arm;
    zaddr target_addr = ins_csd.operands[0].imm;

    // zz_arm_writer_put_ldr_br_b_reg_address(relocate_writer, ARM64_REG_X17, target_addr);
    zz_arm_writer_put_ldr_reg_address(relocate_writer, ARM64_REG_X17, target_addr);
    zz_arm_writer_put_br_reg(relocate_writer, ARM64_REG_X17);
    return true;
}

zboolrelocator_rewrite_bl(Instruction *ins, ZzWriter *relocate_writer)
{
    cs_arm ins_csd = ins->ins_cs->detail->arm;
    zaddr target_addr = ins_csd.operands[0].imm;

    zz_arm_writer_put_ldr_reg_address(relocate_writer, ARM64_REG_X17, target_addr);
    zz_arm_writer_put_blr_reg(relocate_writer, ARM64_REG_X17);
    return true;
}

/*
origin:
1. j.eq [3]

2. [...]
3. [...]

rwrite:
1. j.eq [1.2]
1.1 b [2]
1.2 abs_jmp [3]

2. [...]
3. [...]
*/
zboolrelocator_rewrite_b_cond(Instruction *ins, ZzWriter *relocate_writer)
{
    cs_arm ins_csd = ins->ins_cs->detail->arm;
    zaddr target_addr = ins_csd.operands[0].imm;

    zz_arm_writer_put_b_cond_imm(relocate_writer, ins_csd.cc, 0x8);
    zz_arm_writer_put_b_imm(relocate_writer, 0x4 + 0x14);

    // zz_arm_writer_put_ldr_br_b_reg_address(relocate_writer, ARM64_REG_X17, target_addr);
    zz_arm_writer_put_ldr_reg_address(relocate_writer, ARM64_REG_X17, target_addr);
    zz_arm_writer_put_br_reg(relocate_writer, ARM64_REG_X17);
    return true;
}

zboolrelocator_rewrite_adr(Instruction *ins, ZzWriter *relocate_writer)
{
    cs_arm ins_csd = ins->ins_cs->detail->arm;

    const cs_arm_op dst = ins_csd.operands[0];
    const cs_arm_op label = ins_csd.operands[1];
    zz_arm_writer_put_ldr_reg_address(relocate_writer, dst.reg, label.imm);
    return true;
}