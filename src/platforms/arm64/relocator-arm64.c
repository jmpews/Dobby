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

#include "relocator-arm64.h"
#include "relocator.h"
#include "interceptor.h"

/*
    C6.2.19 B.cond

    C1.2.4 Condition code
 */

Instruction *relocator_read_one(zpointer address, ZzWriter *backup_writer,
                                ZzWriter *relocate_writer)
{
    Instruction *ins = (Instruction *)malloc(sizeof(Instruction));
    cs_insn *ins_cs = disassemble_instruction_at(address);

    if ((ins_cs->size) % 4)
        debug_break();
    ins->address = address;
    ins->ins_cs = ins_cs;
    ins->size = ins_cs->size;
    memcpy(ins->bytes, address, ins_cs->size);

    writer_put_bytes(backup_writer, address, ins_cs->size);

    bool flag = true;
    switch (ins_cs->id)
    {
    case ARM64_INS_B:
        if (branch_is_unconditional(ins))
            flag = relocator_rewrite_b(ins, relocate_writer);
        else
            flag = relocator_rewrite_b_cond(ins, relocate_writer);
        break;
    case ARM64_INS_LDR:
        flag = relocator_rewrite_ldr(ins, relocate_writer);
        break;
    case ARM64_INS_ADR:
    case ARM64_INS_ADRP:
        flag = relocator_rewrite_adr(ins, relocate_writer);
        break;
    case ARM64_INS_BL:
        flag = relocator_rewrite_bl(ins, relocate_writer);
        break;
    default:
        writer_put_bytes(relocate_writer, address, ins_cs->size);
    }
    if (!flag)
        writer_put_bytes(relocate_writer, address, ins_cs->size);
    return ins;
}

void ZzRelocatorBuildInvokeTrampoline(ZzHookFunctionEntry *entry, ZzWriter *backup_writer, ZzWriter *relocate_writer)
{
    bool finished = false;
    zpointer code_addr = entry->target_ptr;
    Instruction *ins;
    zuint jump_instruction_length = 0;
    if(entry->isNearJump) {
        jump_instruction_length = ZzWriterNearJumpInstructionLength();

    } else {
        jump_instruction_length = ZzWriterAbsJumpInstructionLength();
    }

    do
    {
        ins = relocator_read_one(code_addr, backup_writer, relocate_writer);
        code_addr += ins->size;
        free(ins);
        if (entry->hook_type == HOOK_ADDRESS_TYPE && entry->target_end_ptr && code_addr == entry->target_end_ptr)
        {
            ZzWriterPutAbsJump(relocate_writer, entry->on_half_trampoline);
            entry->target_half_ret_addr = (zpointer)relocate_writer->size;
        }
        // hook at half way.
        if ((code_addr - entry->target_ptr) >= jump_instruction_length)
        {
            if (entry->hook_type == HOOK_ADDRESS_TYPE && (!entry->target_end_ptr || code_addr >= entry->target_end_ptr))
            {
                finished = true;
            }
            else if (entry->hook_type == HOOK_FUNCTION_TYPE)
            {
                finished = true;
            }
        }
    } while (!finished);

    // zpointer target_back_addr;
    // target_back_addr = target_addr + backup_writer->pc - backup_writer->base

    // writer_put_ldr_reg_imm(relocate_writer, ARM64_REG_X17, (zuint)0x8);
    // writer_put_br_reg(relocate_writer, ARM64_REG_X17);
    // writer_put_bytes(relocate_writer, (zpointer)&target_back_addr, sizeof(zpointer));
}

bool branch_is_unconditional(Instruction *ins)
{
    cs_arm64 ins_csd = ins->ins_cs->detail->arm64;

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

bool relocator_rewrite_ldr(Instruction *ins, ZzWriter *relocate_writer)
{
    cs_arm64 ins_csd = ins->ins_cs->detail->arm64;
    const cs_arm64_op *dst = &ins_csd.operands[0];
    const cs_arm64_op *src = &ins_csd.operands[1];
    if (src->type != ARM64_OP_IMM)
        return false;
    return true;
}

bool relocator_rewrite_b(Instruction *ins, ZzWriter *relocate_writer)
{
    cs_arm64 ins_csd = ins->ins_cs->detail->arm64;
    zaddr target_addr = ins_csd.operands[0].imm;

    // writer_put_ldr_br_b_reg_address(relocate_writer, ARM64_REG_X17, target_addr);
    writer_put_ldr_reg_address(relocate_writer, ARM64_REG_X17, target_addr);
    writer_put_br_reg(relocate_writer, ARM64_REG_X17);
    return true;
}

bool relocator_rewrite_bl(Instruction *ins, ZzWriter *relocate_writer)
{
    cs_arm64 ins_csd = ins->ins_cs->detail->arm64;
    zaddr target_addr = ins_csd.operands[0].imm;

    writer_put_ldr_reg_address(relocate_writer, ARM64_REG_X17, target_addr);
    writer_put_blr_reg(relocate_writer, ARM64_REG_X17);
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
bool relocator_rewrite_b_cond(Instruction *ins, ZzWriter *relocate_writer)
{
    cs_arm64 ins_csd = ins->ins_cs->detail->arm64;
    zaddr target_addr = ins_csd.operands[0].imm;

    writer_put_b_cond_imm(relocate_writer, ins_csd.cc, 0x8);
    writer_put_b_imm(relocate_writer, 0x4 + 0x14);

    // writer_put_ldr_br_b_reg_address(relocate_writer, ARM64_REG_X17, target_addr);
    writer_put_ldr_reg_address(relocate_writer, ARM64_REG_X17, target_addr);
    writer_put_br_reg(relocate_writer, ARM64_REG_X17);
    return true;
}

bool relocator_rewrite_adr(Instruction *ins, ZzWriter *relocate_writer)
{
    cs_arm64 ins_csd = ins->ins_cs->detail->arm64;

    const cs_arm64_op dst = ins_csd.operands[0];
    const cs_arm64_op label = ins_csd.operands[1];
    writer_put_ldr_reg_address(relocate_writer, dst.reg, label.imm);
    return true;
}