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

#ifndef platforms_arch_arm64_writer_h
#define platforms_arch_arm64_writer_h

// platforms
#include "instructions.h"
#include "regs-arm64.h"
#include "writer-arm64.h"

// hookzz
#include "writer.h"

// zzdeps
#include "hookzz.h"
#include "zzdefs.h"
#include "zzdeps/common/debugbreak.h"
#include "zzdeps/zz.h"

typedef ZzWriter ZzArm64Writer;

ZzArm64Writer *zz_arm64_writer_new(zpointer data_ptr);

void zz_arm64_writer_reset(ZzArm64Writer *self, zpointer data_ptr);

void zz_arm64_writer_init(ZzArm64Writer *self, zpointer target_addr);

zsize zz_arm64_writer_near_jump_range_size();

// ======= user custom =======

void zz_arm64_writer_put_ldr_br_reg_address(ZzWriter *self, arm64_reg reg, zaddr address);
void zz_arm64_writer_put_ldr_blr_b_reg_address(ZzWriter *self, arm64_reg reg, zaddr address);
void zz_arm64_writer_put_ldr_b_reg_address(ZzArm64Writer *self, arm64_reg reg, zaddr address);

// ======= default =======

void zz_arm64_writer_put_ldr_br_b_reg_address(ZzArm64Writer *self, arm64_reg reg, zaddr address);

void zz_arm64_writer_put_b_cond_imm(ZzArm64Writer *self, arm64_cc cc, zsize imm);

void zz_arm64_writer_put_ldr_reg_reg_offset(ZzArm64Writer *self, arm64_reg dst_reg,
                                            arm64_reg src_reg, zsize src_offset);

void zz_arm64_writer_put_str_reg_reg_offset(ZzArm64Writer *self, arm64_reg src_reg,
                                            arm64_reg dst_reg, zsize dst_offset);

void zz_arm64_writer_put_sub_reg_reg_imm(ZzArm64Writer *self, arm64_reg dst_reg, arm64_reg left_reg,
                                         zsize right_value);

void zz_arm64_writer_put_add_reg_reg_imm(ZzArm64Writer *self, arm64_reg dst_reg, arm64_reg left_reg,
                                         zsize right_value);

void zz_arm64_writer_put_ldr_reg_imm(ZzArm64Writer *self, arm64_reg reg, zsize imm);

void zz_arm64_writer_put_br_reg(ZzArm64Writer *self, arm64_reg reg);

void zz_arm64_writer_put_blr_reg(ZzArm64Writer *self, arm64_reg reg);

void zz_arm64_writer_put_bytes(ZzArm64Writer *self, zbyte *data, zuint data_size);

void zz_arm64_writer_put_instruction(ZzArm64Writer *self, zuint32 insn);

void zz_arm64_writer_put_b_imm(ZzArm64Writer *self, zsize imm);

#endif