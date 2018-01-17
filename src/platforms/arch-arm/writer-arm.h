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

#ifndef platforms_arch_arm_writer_arm_h
#define platforms_arch_arm_writer_arm_h

#include <string.h>

#include "hookzz.h"
#include "kitzz.h"

#include "macros.h"
#include "memory.h"
#include "writer.h"

#include "instructions.h"
#include "reader-arm.h"
#include "regs-arm.h"
#include "writer-arm.h"

typedef ZzAssemblerWriter ZzARMAssemblerWriter;
ZzARMAssemblerWriter *zz_arm_writer_new(zz_ptr_t data_ptr);
void zz_arm_writer_init(ZzARMAssemblerWriter *self, zz_ptr_t data_ptr);
void zz_arm_writer_reset(ZzARMAssemblerWriter *self, zz_ptr_t data_ptr);
zz_size_t zz_arm_writer_near_jump_range_size();

// ------- user custom -------

void zz_arm_writer_put_ldr_b_reg_address(ZzARMAssemblerWriter *self, ZzARMReg reg, zz_addr_t address);
void zz_arm_writer_put_bx_to_thumb(ZzARMAssemblerWriter *self);

// ------- architecture default -------

void zz_arm_writer_put_bytes(ZzARMAssemblerWriter *self, char *data, zz_size_t data_size);

void zz_arm_writer_put_instruction(ZzARMAssemblerWriter *self, uint32_t insn);

void zz_arm_writer_put_b_imm(ZzARMAssemblerWriter *self, uint32_t imm);

void zz_arm_writer_put_bx_reg(ZzARMAssemblerWriter *self, ZzARMReg reg);

void zz_arm_writer_put_nop(ZzARMAssemblerWriter *self);

void zz_arm_writer_put_ldr_reg_reg_imm(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, int32_t imm);

void zz_arm_writer_put_str_reg_reg_imm(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, int32_t imm);

void zz_arm_writer_put_ldr_reg_imm_literal(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, int32_t imm);

void zz_arm_writer_put_ldr_reg_reg_imm_index(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, int32_t imm,
                                             bool index);

void zz_arm_writer_put_ldr_reg_reg_imm_A1(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, uint32_t imm, bool P,
                                          bool U, bool W);

void zz_arm_writer_put_ldr_reg_address(ZzARMAssemblerWriter *self, ZzARMReg reg, zz_addr_t address);

void zz_arm_writer_put_add_reg_reg_imm(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, uint32_t imm);

void zz_arm_writer_put_sub_reg_reg_imm(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, uint32_t imm);

void zz_arm_writer_put_push_reg(ZzARMAssemblerWriter *self, ZzARMReg reg);

void zz_arm_writer_put_pop_reg(ZzARMAssemblerWriter *self, ZzARMReg reg);

ZzLiteralInstruction *zz_arm_writer_put_ldr_b_reg_relocate_address(ZzARMAssemblerWriter *self, ZzARMReg reg, zz_addr_t address,
                                                                   ZzLiteralInstruction **literal_insn_ptr);

ZzLiteralInstruction *zz_arm_writer_put_ldr_reg_relocate_address(ZzARMAssemblerWriter *self, ZzARMReg reg, zz_addr_t address,
                                                                 ZzLiteralInstruction **literal_insn_ptr);
#endif