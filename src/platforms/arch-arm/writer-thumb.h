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

#ifndef platforms_arch_arm_writer_thumb_h
#define platforms_arch_arm_writer_thumb_h

#include <string.h>

#include "hookzz.h"
#include "kitzz.h"

#include "macros.h"
#include "memory.h"
#include "writer.h"

#include "instructions.h"
#include "reader-thumb.h"
#include "regs-arm.h"
#include "writer-thumb.h"

typedef ZzAssemblerWriter ZzThumbAssemblerWriter;

typedef enum _ZzThumbMemoryOperation { ZZ_THUMB_MEMORY_LOAD, ZZ_THUMB_MEMORY_STORE } ZzThumbMemoryOperation;

// ------- user custom -------

void zz_thumb_writer_put_ldr_b_reg_address(ZzThumbAssemblerWriter *self, ZzARMReg reg, zz_addr_t address);

// ------- architecture default -------

ZzThumbAssemblerWriter *zz_thumb_writer_new(zz_ptr_t data_ptr);

void zz_thumb_writer_init(ZzThumbAssemblerWriter *self, zz_ptr_t data_ptr);

void zz_thumb_writer_reset(ZzThumbAssemblerWriter *self, zz_ptr_t data_ptr);

zz_size_t zz_thumb_writer_near_jump_range_size();

void zz_thumb_writer_put_nop(ZzThumbAssemblerWriter *self);

void zz_thumb_writer_put_bytes(ZzThumbAssemblerWriter *self, char *data, zz_size_t data_size);

void zz_thumb_writer_put_instruction(ZzThumbAssemblerWriter *self, uint16_t insn);

void zz_thumb_writer_put_b_imm(ZzThumbAssemblerWriter *self, uint32_t imm);

void zz_thumb_writer_put_bx_reg(ZzThumbAssemblerWriter *self, ZzARMReg reg);

void zz_thumb_writer_put_blx_reg(ZzThumbAssemblerWriter *self, ZzARMReg reg);

void zz_thumb_writer_put_branch_imm(ZzThumbAssemblerWriter *self, uint32_t imm, bool link, bool thumb);

void zz_thumb_writer_put_bl_imm(ZzThumbAssemblerWriter *self, uint32_t imm);

void zz_thumb_writer_put_blx_imm(ZzThumbAssemblerWriter *self, uint32_t imm);

void zz_thumb_writer_put_b_imm32(ZzThumbAssemblerWriter *self, uint32_t imm);

void zz_thumb_writer_put_ldr_reg_imm(ZzThumbAssemblerWriter *self, ZzARMReg reg, int32_t imm);

void zz_thumb_writer_put_ldr_reg_address(ZzThumbAssemblerWriter *self, ZzARMReg reg, zz_addr_t address);

static void zz_thumb_writer_put_transfer_reg_reg_offset(ZzThumbAssemblerWriter *self, ZzThumbMemoryOperation operation,
                                                        ZzARMReg left_reg, ZzARMReg right_reg, int32_t right_offset);

void zz_thumb_writer_put_ldr_reg_reg_offset(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg,
                                            int32_t src_offset);

void zz_thumb_writer_put_str_reg_reg_offset(ZzThumbAssemblerWriter *self, ZzARMReg src_reg, ZzARMReg dst_reg,
                                            int32_t dst_offset);

void zz_thumb_writer_put_str_index_reg_reg_offset(ZzThumbAssemblerWriter *self, ZzARMReg src_reg, ZzARMReg dst_reg,
                                                  int32_t dst_offset, bool index);

void zz_thumb_writer_put_ldr_index_reg_reg_offset(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg,
                                                  int32_t src_offset, bool index);

void zz_thumb_writer_put_str_reg_reg(ZzThumbAssemblerWriter *self, ZzARMReg src_reg, ZzARMReg dst_reg);

void zz_thumb_writer_put_ldr_reg_reg(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg);

void zz_thumb_writer_put_add_reg_imm(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, int32_t imm);

void zz_thumb_writer_put_sub_reg_imm(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, int32_t imm);

void zz_thumb_writer_put_add_reg_reg_imm(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg left_reg, int32_t right_value);

void zz_thumb_writer_put_sub_reg_reg_imm(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg left_reg, int32_t right_value);

void zz_thumb_writer_put_push_reg(ZzThumbAssemblerWriter *self, ZzARMReg reg);

void zz_thumb_writer_put_pop_reg(ZzThumbAssemblerWriter *self, ZzARMReg reg);

void zz_thumb_writer_put_add_reg_reg_reg(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg left_reg, ZzARMReg right_reg);

ZzLiteralInstruction *zz_thumb_writer_put_ldr_reg_relocate_address(ZzThumbAssemblerWriter *self, ZzARMReg reg, zz_addr_t address,
                                                                   ZzLiteralInstruction **literal_insn_ptr);

ZzLiteralInstruction *zz_thumb_writer_put_ldr_b_reg_relocate_address(ZzThumbAssemblerWriter *self, ZzARMReg reg,
                                                                     zz_addr_t address,
                                                                     ZzLiteralInstruction **literal_insn_ptr);
#endif