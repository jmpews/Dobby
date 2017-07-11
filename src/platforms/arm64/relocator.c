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

#include "relocator.h"
#include "../../debugbreak.h"
#include <string.h>

Instruction *relocator_read_one(zpointer address, ZZWriter *backup_writer, ZZWriter *relocate_writer) {
    Instruction *ins = (Instruction *)malloc(sizeof(Instruction));
    cs_insn *ins_cs = disassemble_instruction_at(address);

    if((ins_cs->size) % 4)
        debug_break();
    ins->address = address;
    ins->ins_cs = ins_cs;
    ins->size = ins_cs->size;
    memcpy(ins->bytes, address, ins_cs->size);

    writer_put_bytes(backup_writer, address, ins_cs->size);
    
    switch(ins_cs->id) {
        case ARM64_INS_B:
            relocator_rewrite_b(ins, relocate_writer);
            break;
        default:
            writer_put_bytes(relocate_writer, address, ins_cs->size);
    }
    return ins;
}

void relocator_rewrite_b(Instruction *ins, ZZWriter *relocate_writer) {
    cs_arm64 ins_csd = ins->ins_cs->detail->arm64;
    zaddr target_addr = ins_csd.operands[0].imm;

    writer_put_ldr_reg_imm(relocate_writer, ARM64_REG_X16, (zuint)0xc8);
    writer_put_b_imm(relocate_writer, (zaddr)0xc);
    writer_put_bytes(relocate_writer, (zpointer)&target_addr, sizeof(target_addr));

    writer_put_br_reg(relocate_writer, ARM64_REG_X16);
}
