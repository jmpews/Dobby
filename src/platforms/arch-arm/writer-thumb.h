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

// platforms
#include "instructions.h"
#include "reader-thumb.h"
#include "regs-arm.h"
#include "writer-thumb.h"

// hookzz
#include "writer.h"

// zzdeps
#include "hookzz.h"
#include "zzdefs.h"
#include "zzdeps/common/debugbreak.h"
#include "zzdeps/zz.h"

typedef ZzWriter ZzThumbWriter;

typedef enum _ZzThumbMemoryOperation { ZZ_THUMB_MEMORY_LOAD, ZZ_THUMB_MEMORY_STORE } ZzThumbMemoryOperation;

// ------- user custom -------

zpointer zz_thumb_writer_put_ldr_b_reg_address(ZzThumbWriter *self, ZzReg reg, zaddr address);

// ------- architecture default -------

ZzThumbWriter *zz_thumb_writer_new(zpointer data_ptr);
void zz_thumb_writer_init(ZzThumbWriter *self, zpointer data_ptr);
void zz_thumb_writer_reset(ZzThumbWriter *self, zpointer data_ptr);
zpointer zz_thumb_writer_put_nop(ZzThumbWriter *self);
zpointer zz_thumb_writer_put_bytes(ZzThumbWriter *self, zbyte *data, zuint data_size);
zpointer zz_thumb_writer_put_instruction(ZzThumbWriter *self, uint16_t insn);
zpointer zz_thumb_writer_put_b_imm(ZzThumbWriter *self, zuint32 imm);
zpointer zz_thumb_writer_put_bx_reg(ZzThumbWriter *self, ZzReg reg);
zpointer zz_thumb_writer_put_blx_reg(ZzThumbWriter *self, ZzReg reg);
zpointer zz_thumb_writer_put_branch_imm(ZzThumbWriter *self, zuint32 imm, zbool link, zbool thumb);
zpointer zz_thumb_writer_put_bl_imm(ZzThumbWriter *self, zuint32 imm);
zpointer zz_thumb_writer_put_blx_imm(ZzThumbWriter *self, zuint32 imm);
zpointer zz_thumb_writer_put_b_imm32(ZzThumbWriter *self, zuint32 imm);

zpointer zz_thumb_writer_put_ldr_reg_imm(ZzThumbWriter *self, ZzReg reg, zint32 imm);
zpointer zz_thumb_writer_put_ldr_reg_address(ZzThumbWriter *self, ZzReg reg, zaddr address);

static zpointer zz_thumb_writer_put_transfer_reg_reg_offset(ZzThumbWriter *self, ZzThumbMemoryOperation operation,
                                                            ZzReg left_reg, ZzReg right_reg, zint32 right_offset);
zpointer zz_thumb_writer_put_ldr_reg_reg_offset(ZzThumbWriter *self, ZzReg dst_reg, ZzReg src_reg, zint32 src_offset);
zpointer zz_thumb_writer_put_str_reg_reg_offset(ZzThumbWriter *self, ZzReg src_reg, ZzReg dst_reg, zint32 dst_offset);
zpointer zz_thumb_writer_put_str_index_reg_reg_offset(ZzThumbWriter *self, ZzReg src_reg, ZzReg dst_reg,
                                                      zint32 dst_offset, zbool index);
zpointer zz_thumb_writer_put_ldr_index_reg_reg_offset(ZzThumbWriter *self, ZzReg dst_reg, ZzReg src_reg,
                                                      zint32 src_offset, zbool index);
zpointer zz_thumb_writer_put_str_reg_reg(ZzThumbWriter *self, ZzReg src_reg, ZzReg dst_reg);
zpointer zz_thumb_writer_put_ldr_reg_reg(ZzThumbWriter *self, ZzReg dst_reg, ZzReg src_reg);
zpointer zz_thumb_writer_put_add_reg_imm(ZzThumbWriter *self, ZzReg dst_reg, zint32 imm);
zpointer zz_thumb_writer_put_sub_reg_imm(ZzThumbWriter *self, ZzReg dst_reg, zint32 imm);
zpointer zz_thumb_writer_put_add_reg_reg_imm(ZzThumbWriter *self, ZzReg dst_reg, ZzReg left_reg, zint32 right_value);
zpointer zz_thumb_writer_put_sub_reg_reg_imm(ZzThumbWriter *self, ZzReg dst_reg, ZzReg left_reg, zint32 right_value);
zsize zz_thumb_writer_near_jump_range_size();
#endif