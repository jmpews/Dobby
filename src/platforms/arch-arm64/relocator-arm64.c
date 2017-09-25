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

#include "relocator-arm64.h"
#include <string.h>

/*
    C6.2.19 B.cond

    C1.2.4 Condition code
 */

#define MAX_RELOCATOR_INSTRUCIONS_SIZE 64

void zz_arm64_relocator_init(ZzArm64Relocator *relocator, zpointer input_code,
                             ZzArm64Writer *output) {
    cs_err err;
    err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &relocator->capstone);
    if (err) {
        Xerror("Failed on cs_open() with error returned: %u\n", err);
        exit(-1);
    }
    cs_option(relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);

    relocator->inpos = 0;
    relocator->outpos = 0;

    relocator->input_start = input_code;
    relocator->input_cur = input_code;
    relocator->input_pc = (zaddr)input_code;
    relocator->input_insns =
        (Instruction *)malloc(MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(Instruction));

    memset(relocator->input_insns, 0, MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(Instruction));

    relocator->output = output;
}

void zz_arm64_relocator_reset(ZzArm64Relocator *self, zpointer input_code, ZzArm64Writer *output) {
    self->input_cur = input_code;
    self->input_start = input_code;
    self->input_pc = (zaddr)input_code;

    self->inpos = 0;
    self->outpos = 0;

    self->output = output;
}

// zsize zz_arm64_relocator_read_one(ZzArm64Relocator *self, Instruction *instruction) {
//     cs_insn **cs_insn_ptr, *cs_insn;
//     Instruction insn = self->input_insns[self->inpos];
//     cs_insn_ptr = &insn.cs_insn;

//     if (cs_disasm(self->capstone, self->input_cur, 4, self->input_pc, 1, cs_insn_ptr) != 1) {
//         return 0;
//     }

//     cs_insn = *cs_insn_ptr;

//     // zbool flag = true;
//     // switch (cs_insn->id) {
//     // case ARM64_INS_B:
//     //     if (branch_is_unconditional(ins))
//     //         flag = relocator_rewrite_b(ins, relocate_writer);
//     //     else
//     //         flag = relocator_rewrite_b_cond(ins, relocate_writer);
//     //     break;
//     // case ARM64_INS_LDR:
//     //     flag = relocator_rewrite_ldr(ins, relocate_writer);
//     //     break;
//     // case ARM64_INS_ADR:
//     // case ARM64_INS_ADRP:
//     //     flag = relocator_rewrite_adr(ins, relocate_writer);
//     //     break;
//     // case ARM64_INS_BL:
//     //     flag = relocator_rewrite_bl(ins, relocate_writer);
//     //     break;
//     // default:
//     //     zz_arm64_writer_put_bytes(relocate_writer, address, cs_insn->size);
//     // }
//     // if (!flag)
//     //     zz_arm64_writer_put_bytes(relocate_writer, address, cs_insn->size);

//     if (instruction != NULL)
//         *instruction = insn;

//     self->input_cur += cs_insn->size;
//     self->input_pc += cs_insn->size;

//     return self->input_cur - self->input_start;
// }

zsize zz_arm64_relocator_read_one(ZzArm64Relocator *self, Instruction *instruction) {
    cs_insn **cs_insn_ptr, *cs_insn;
    Instruction *insn = &self->input_insns[self->inpos];
    cs_insn_ptr = &insn->cs_insn;

    if (*cs_insn_ptr == NULL)
        *cs_insn_ptr = cs_malloc(self->capstone);

    // http://www.capstone-engine.org/iteration.html
    uint64_t address;
    size_t size;
    const uint8_t *code;

    code = self->input_cur;
    size = 4;
    address = self->input_pc;
    cs_insn = *cs_insn_ptr;

    if (!cs_disasm_iter(self->capstone, &code, &size, &address, cs_insn)) {
        return 0;
    }

    switch (cs_insn->id) {}

    self->inpos++;

    if (instruction != NULL)
        instruction = insn;

    self->input_cur += cs_insn->size;
    self->input_pc += cs_insn->size;

    return self->input_cur - self->input_start;
}

void zz_arm64_relocator_write_all(ZzArm64Relocator *self) {
    zuint count = 0;
    while (zz_arm64_relocator_write_one(self))
        count++;
}

zbool zz_arm64_relocator_write_one(ZzArm64Relocator *self) {
    Instruction *insn;
    cs_insn *cs_insn;
    zbool rewritten = false;

    insn = &self->input_insns[self->outpos];
    cs_insn = insn->cs_insn;

    if (self->inpos != self->outpos) {
        self->outpos++;
    } else {
        return false;
    }

    switch (cs_insn->id) {}
    if (!rewritten)
        zz_arm64_writer_put_bytes(self->output, cs_insn->bytes, cs_insn->size);
    return true;
}

void zz_arm64_relocator_try_relocate(zpointer address, zuint min_bytes, zuint *max_bytes) {
    *max_bytes = 16;
    return;
}

// void ZzRelocatorBuildInvokeTrampoline(ZzHookFunctionEntry *entry,
//                                       ZzArm64Writer *backup_writer,
//                                       ZzArm64Writer *relocate_writer) {
//     zbool finished = false;
//     zpointer code_addr = entry->target_ptr;
//     Instruction *ins;
//     zuint jump_instruction_length = 0;
//     if (entry->isNearJump) {
//         jump_instruction_length = ZzArm64WriterNearJumpInstructionLength();

//     } else {
//         jump_instruction_length = ZzArm64WriterAbsJumpInstructionLength();
//     }

//     do {
//         ins = relocator_read_one(code_addr, backup_writer, relocate_writer);
//         code_addr += ins->size;
//         free(ins);
//         if (entry->hook_type == HOOK_ADDRESS_TYPE && entry->target_end_ptr &&
//             code_addr == entry->target_end_ptr) {
//             ZzArm64WriterPutAbsJump(relocate_writer,
//             entry->on_half_trampoline); entry->target_half_ret_addr =
//             (zpointer)relocate_writer->size;
//         }
//         // hook at half way.
//         if ((code_addr - entry->target_ptr) >= jump_instruction_length) {
//             if (entry->hook_type == HOOK_ADDRESS_TYPE &&
//                 (!entry->target_end_ptr ||
//                  code_addr >= entry->target_end_ptr)) {
//                 finished = true;
//             } else if (entry->hook_type == HOOK_FUNCTION_TYPE) {
//                 finished = true;
//             }
//         }
//     } while (!finished);

//     // zpointer target_back_addr;
//     // target_back_addr = target_addr + backup_writer->pc -
//     backup_writer->base

//     // zz_arm64_writer_put_ldr_reg_imm(relocate_writer, ARM64_REG_X17,
//     // (zuint)0x8); zz_arm64_writer_put_br_reg(relocate_writer,
//     ARM64_REG_X17);
//     // zz_arm64_writer_put_bytes(relocate_writer,
//     (zpointer)&target_back_addr,
//     // sizeof(zpointer));
// }

// zbool branch_is_unconditional(Instruction *ins) {
//     cs_arm64 ins_csd = ins->cs_insn->detail->arm64;

//     switch (ins_csd.cc) {
//     case ARM64_CC_INVALID:
//     case ARM64_CC_AL:
//     case ARM64_CC_NV:
//         return true;
//     default:
//         return false;
//     }
// }

// zbool relocator_rewrite_ldr(Instruction *ins, ZzArm64Writer *relocate_writer)
// {
//     cs_arm64 ins_csd = ins->cs_insn->detail->arm64;
//     const cs_arm64_op *dst = &ins_csd.operands[0];
//     const cs_arm64_op *src = &ins_csd.operands[1];
//     if (src->type != ARM64_OP_IMM)
//         return false;
//     return true;
// }

// zbool relocator_rewrite_b(Instruction *ins, ZzArm64Writer *relocate_writer) {
//     cs_arm64 ins_csd = ins->cs_insn->detail->arm64;
//     zaddr target_addr = ins_csd.operands[0].imm;

//     // zz_arm64_writer_put_ldr_br_b_reg_address(relocate_writer,
//     ARM64_REG_X17,
//     // target_addr);
//     zz_arm64_writer_put_ldr_reg_address(relocate_writer, ARM64_REG_X17,
//                                         target_addr);
//     zz_arm64_writer_put_br_reg(relocate_writer, ARM64_REG_X17);
//     return true;
// }

// zbool relocator_rewrite_bl(Instruction *ins, ZzArm64Writer *relocate_writer)
// {
//     cs_arm64 ins_csd = ins->cs_insn->detail->arm64;
//     zaddr target_addr = ins_csd.operands[0].imm;

//     zz_arm64_writer_put_ldr_reg_address(relocate_writer, ARM64_REG_X17,
//                                         target_addr);
//     zz_arm64_writer_put_blr_reg(relocate_writer, ARM64_REG_X17);
//     return true;
// }

// /*
//     origin:
//         1. j.eq [3]

//         2. [...]
//         3. [...]

//     rwrite:
//         1. j.eq [1.2]
//         1.1 b [2]
//         1.2 abs_jmp [3]

//         2. [...]
//         3. [...]
//  */
// zbool relocator_rewrite_b_cond(Instruction *ins,
//                                ZzArm64Writer *relocate_writer) {
//     cs_arm64 ins_csd = ins->cs_insn->detail->arm64;
//     zaddr target_addr = ins_csd.operands[0].imm;

//     zz_arm64_writer_put_b_cond_imm(relocate_writer, ins_csd.cc, 0x8);
//     zz_arm64_writer_put_b_imm(relocate_writer, 0x4 + 0x14);

//     // zz_arm64_writer_put_ldr_br_b_reg_address(relocate_writer,
//     ARM64_REG_X17,
//     // target_addr);
//     zz_arm64_writer_put_ldr_reg_address(relocate_writer, ARM64_REG_X17,
//                                         target_addr);
//     zz_arm64_writer_put_br_reg(relocate_writer, ARM64_REG_X17);
//     return true;
// }

// zbool relocator_rewrite_adr(Instruction *ins, ZzArm64Writer *relocate_writer)
// {
//     cs_arm64 ins_csd = ins->cs_insn->detail->arm64;

//     const cs_arm64_op dst = ins_csd.operands[0];
//     const cs_arm64_op label = ins_csd.operands[1];
//     zz_arm64_writer_put_ldr_reg_address(relocate_writer, dst.reg, label.imm);
//     return true;
// }