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

#include "reader.h"

static csh handle;

void capstone_init(void) {
    cs_err err;

#if defined(__x86_64__)
    err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
#elif defined(__arm64__)
    err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle);
#endif
    if (err) {
        Xerror("Failed on cs_open() with error returned: %u\n", err);
        exit(-1);
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
}

cs_insn *disassemble_instruction_at(zpointer address) {
    if (!handle)
        capstone_init();
    cs_insn *insn;
    size_t count;
    count = cs_disasm(handle, address, 16, (unsigned long) address, 0, &insn);
    return insn;
}

// void relocator_read_one(Instruction *old_ins, Instruction *new_ins)
// {

// #if defined(_M_X64) || defined(__x86_64__)
//     CALL_ABS call = {
//         0xFF, 0x15, 0x00000002, // FF15 00000002: CALL [RIP+8]
//         0xEB, 0x08,             // EB 08:         JMP +10
//         0x0000000000000000ULL   // Absolute destination address
//     };
//     JMP_ABS jmp = {
//         0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
//         0x0000000000000000ULL   // Absolute destination address
//     };
//     JCC_ABS jcc = {
//         0x70, 0x0E,             // 7* 0E:         J** +16
//         0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
//         0x0000000000000000ULL   // Absolute destination address
//     };
// #else
//     CALL_REL call = {
//         0xE8,      // E8 xxxxxxxx: CALL +5+xxxxxxxx
//         0x00000000 // Relative destination address
//     };
//     JMP_REL jmp = {
//         0xE9,      // E9 xxxxxxxx: JMP +5+xxxxxxxx
//         0x00000000 // Relative destination address
//     };
//     JCC_REL jcc = {
//         0x0F, 0x80, // 0F8* xxxxxxxx: J** +6+xxxxxxxx
//         0x00000000  // Relative destination address
//     };
// #endif

//     // capstone ins
//     cs_insn *ins_cs = disassemble_instruction_at(old_ins->address);

//     // capstone ins detail
//     // cs_detail *ins_csd = ins_cs->detail->x86;
//     cs_x86 ins_csd = ins_cs->detail->x86;

//     old_ins->ins_cs = ins_cs;
//     old_ins->size = ins_cs->size;
//     uint8_t needFix = 0;

//     zpointer copy_ins_start;
//     uint8_t copy_ins_size;

//     // https://c9x.me/x86/html/file_module_x86_id_146.html

//     /*
//     ATTENTION: why 0x01 ^ cond? because of use `method_1`

//     origin:
//         1: je <3>
//         2: push rax;
//         3: push rbx;

//     method_1:
//         1: jne <3>
//         2: jmp(abs) <4>
//         3: push rax
//         4: push rbx

//     method_2:
//         1: je <3>
//         2: jmp(near) <4>
//         3: jmp(abs) <5>
//         4: push rax
//         5: push rbx

//     */
//     if ((ins_csd.opcode[0] & 0xF0) == 0x70 || (ins_csd.opcode[0] & 0xFC) == 0xE0 || (ins_csd.opcode[1] & 0xF0) == 0x80)
//     {
//         // the imm is calculate by capstone, so the imm is dest;
//         zpointer dest = (zpointer)ins_csd.operands[0].imm;
//         zpointer offset = (zpointer)ins_csd.operands[0].imm - old_ins->address - old_ins->size;

//         zpointer new_offset = dest - new_ins->address + sizeof(JMP_ABS);

//         if (dest > new_ins->address && dest < (new_ins->address + sizeof(JMP_ABS)))
//         {
//             zpointer internal_jmp_dest = 0;
//             if (internal_jmp_dest < dest)
//             {
//                 internal_jmp_dest = dest;
//                 Xerror("origin: %p, trampoline: %p is trampoline-internal-jmp !", old_ins->address, new_ins->address);
//                 return;
//             }
//         }
//         else
//         {
//             needFix = 1;
//             uint8_t cond = ((ins_csd.opcode[0] != 0x0F ? ins_csd.opcode[0] : ins_csd.opcode[2]) & 0x0F);

//             jcc.opcode = 0x71 ^ cond;
//             jcc.address = dest;
//         }

//         copy_ins_start = &jcc;
//         copy_ins_size = sizeof(jcc);
//     }

//     if (needFix)
//     {
//         new_ins->size = copy_ins_size;
//         memcpy(new_ins->bytes, copy_ins_start, copy_ins_size);
//     }
//     else
//     {
//         /*
//             yes, we can just write to new_ins->address, according to the module of design patterns, we can't do `write` operation at here.
//             memcpy(new_ins->address, old_ins->address, old_ins->size);
//          */
//         new_ins->size = old_ins->size;
//         memcpy(new_ins->bytes, old_ins->address, old_ins->size);
//     }
//     memcpy(old_ins->bytes, old_ins->address, old_ins->size);
// }

// void relocator_invoke_trampoline(ZZTrampoline *trampoline, zpointer target, uint8_t *read_size, zpointer read_backup)
// {
//     // current read position in target function
//     uint8_t old_size = 0;
//     // current write position in trampoline->data
//     uint8_t new_size = 0;

//     zpointer old_pos = target;
//     zpointer new_pos = trampoline->codeslice->data;

//     bool finished = false;

//     Instruction new_ins;
//     Instruction old_ins;

//     do
//     {
//         memset(&old_ins, 0, sizeof(Instruction));
//         memset(&new_ins, 0, sizeof(Instruction));

//         old_ins.address = old_pos;
//         new_ins.address = new_pos;

//         relocator_read_one(&old_ins, &new_ins);
//         memcpy(read_backup + old_size, old_ins.bytes, old_ins.size);
//         memcpy(trampoline->codeslice->data + new_size, new_ins.bytes, new_ins.size);

//         old_size += old_ins.size;
//         new_size += new_ins.size;

//         old_pos = target + old_size;
//         new_pos = trampoline->codeslice->data + new_size;

//         if (old_size >= sizeof(JMP_METHOD))
//         {
//             finished = true;
//         }

//     } while (!finished);

//     Instruction *jmp_ins = writer_put_jmp(target + old_size);
//     memcpy(trampoline->codeslice->data + new_size, jmp_ins->bytes, jmp_ins->size);
//     new_size += jmp_ins->size;
//     free(jmp_ins);

//     *read_size = old_size;
//     trampoline->size = new_size;
//     return;
// }

// /*
// uint8_t relocator_invoke_trampoline(ZZTrampoline *trampoline, zpointer target,uint8_t *read_size) {
//     zpointer data = trampoline->data;

//     // current read position in target function
//     uint8_t oldPos = 0;
//     // current write position in trampoline->data
//     uint8_t newPos = 0;

//     bool finished = false;

//     zpointer copy_ins_start;
//     uint8_t copy_ins_size;


// #if defined(_M_X64) || defined(__x86_64__)
//     CALL_ABS call = {
//         0xFF, 0x15, 0x00000002, // FF15 00000002: CALL [RIP+8]
//         0xEB, 0x08,             // EB 08:         JMP +10
//         0x0000000000000000ULL   // Absolute destination address
//     };
//     JMP_ABS jmp = {
//         0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
//         0x0000000000000000ULL   // Absolute destination address
//     };
//     JCC_ABS jcc = {
//         0x70, 0x0E,             // 7* 0E:         J** +16
//         0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
//         0x0000000000000000ULL   // Absolute destination address
//     };
// #else
//     CALL_REL call = {
//         0xE8,                   // E8 xxxxxxxx: CALL +5+xxxxxxxx
//         0x00000000              // Relative destination address
//     };
//     JMP_REL jmp = {
//         0xE9,                   // E9 xxxxxxxx: JMP +5+xxxxxxxx
//         0x00000000              // Relative destination address
//     };
//     JCC_REL jcc = {
//         0x0F, 0x80,             // 0F8* xxxxxxxx: J** +6+xxxxxxxx
//         0x00000000              // Relative destination address
//     };
// #endif

//     do
//     {
//         zpointer oldInsPos = trampoline->target + oldPos
//         zpointer newInsPos = trampoline->data + newPos;

//         cs_insn *insn = disassemble_instruction_at(oldInsPos);

//         // ins detail
//         cs_detail *insd = insn->detail->x86;

//         copy_ins_start = oldInsPos;
//         copy_ins_size = insn->size;

//         // jmp to the rest-code
//         if(oldPos >= sizeof(JMP_ABS)) {
//             jmp.address = oldInsPos;
//             copy_ins_start = &jmp;
//             copy_ins_size = sizeof(jmp)
//             finished = true;
//         }
//         else if((insd.opcode[0] & 0xF0) == 0x70
//         || (insd->opcode[0] & 0xFC) == 0xE0
//         || (insd->opcode[1] & 0xF0) == 0x80)
//         {
//             zpointer dest = ins_detai.operands[0].imm;
//             if(dest > trampoline->target && dest < (trampoline->target+sizeof(JMP_ABS))) {
//                 zpointer internal_jmp_dest = 0;
//                 if(internal_jmp_dest < dest) {
//                     internal_jmp_dest = dest;
//                     Xerror("origin: %p, trampoline: %p is trampoline-internal-jmp !", oldInsPos, newInsPos);
//                 }
//             } else {
//                 uint8_t cond = ((insd.opcode[0] != 0x0F ? insd.opcode[0] : insd.opcode[2]) & 0x0F);
//                 jcc.opcode  = 0x71 ^ cond;
//                 jcc.address = dest;
//             }

//             copy_ins_start = &jcc;
//             copy_ins_size = sizeof(jcc);
//         }

//         // trampoline function too large.
//         if((newPos + new_ins_size) > trampoline->data->size) {
//             return false;
//         }

//         memcpy(trampoline->data+newPos, copy_ins_start, copy_ins_size);

//         newPos += copy_ins_size;
//         oldPos +=  insn->size;

//     } while(!finish)
// }
// */
