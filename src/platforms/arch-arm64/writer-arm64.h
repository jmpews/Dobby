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

#ifndef platforms_arch_arm64_writer_h
#define platforms_arch_arm64_writer_h

#include "zkit.h"

#include "memory.h"
#include "writer.h"

#include "instructions.h"
#include "regs-arm64.h"
#include "writer-arm64.h"

#define MAX_INSN_SIZE 256

typedef struct _ZzARM64AssemblerWriter {
    ZzARM64Instruction *insns[MAX_INSN_SIZE];
    zz_size_t insn_size;
    zz_addr_t w_start_address;
    zz_addr_t w_current_address;
    zz_addr_t start_pc;
    zz_addr_t current_pc;
    zz_size_t size;
} ZzARM64AssemblerWriter;

ZzARM64AssemblerWriter *arm64_writer_new(zz_ptr_t data_ptr);
void arm64_writer_init(ZzARM64AssemblerWriter *self, zz_ptr_t data_ptr, zz_addr_t target_ptr);
void arm64_writer_reset(ZzARM64AssemblerWriter *self, zz_ptr_t data_ptr, zz_addr_t target_ptr);
void arm64_writer_free(ZzARM64AssemblerWriter *self);
zz_size_t arm64_writer_near_jump_range_size();

// ======= user custom =======

void arm64_writer_put_ldr_br_reg_address(ZzARM64AssemblerWriter *self, ZzARM64Reg reg, zz_addr_t address);

void arm64_writer_put_ldr_blr_b_reg_address(ZzARM64AssemblerWriter *self, ZzARM64Reg reg, zz_addr_t address);

void arm64_writer_put_ldr_b_reg_address(ZzARM64AssemblerWriter *self, ZzARM64Reg reg, zz_addr_t address);

void arm64_writer_put_ldr_br_b_reg_address(ZzARM64AssemblerWriter *self, ZzARM64Reg reg, zz_addr_t address);

// ======= default =======

void arm64_writer_put_ldr_reg_imm(ZzARM64AssemblerWriter *self, ZzARM64Reg reg, uint32_t offset);

void arm64_writer_put_str_reg_reg_offset(ZzARM64AssemblerWriter *self, ZzARM64Reg src_reg, ZzARM64Reg dst_reg,
                                         uint64_t offset);

void arm64_writer_put_ldr_reg_reg_offset(ZzARM64AssemblerWriter *self, ZzARM64Reg dst_reg, ZzARM64Reg src_reg,
                                         uint64_t offset);

void arm64_writer_put_br_reg(ZzARM64AssemblerWriter *self, ZzARM64Reg reg);

void arm64_writer_put_blr_reg(ZzARM64AssemblerWriter *self, ZzARM64Reg reg);

void arm64_writer_put_b_imm(ZzARM64AssemblerWriter *self, uint64_t offset);

void arm64_writer_put_b_cond_imm(ZzARM64AssemblerWriter *self, uint32_t condition, uint64_t imm);

void arm64_writer_put_add_reg_reg_imm(ZzARM64AssemblerWriter *self, ZzARM64Reg dst_reg, ZzARM64Reg left_reg,
                                      uint64_t imm);

void arm64_writer_put_sub_reg_reg_imm(ZzARM64AssemblerWriter *self, ZzARM64Reg dst_reg, ZzARM64Reg left_reg,
                                      uint64_t imm);

void arm64_writer_put_bytes(ZzARM64AssemblerWriter *self, char *data, zz_size_t size);

void arm64_writer_put_instruction(ZzARM64AssemblerWriter *self, uint32_t insn);

#endif