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

#include "hookzz.h"

#include "instructions.h"
#include "writer-arm64.h"
#include "regs-arm64.h"

void zz_arm64_writer_put_ldr_reg_address(ZzWriter *self, arm64_reg reg, zaddr address);

void zz_arm64_writer_put_ldr_br_b_reg_address(ZzWriter *self, arm64_reg reg,
                                     zaddr address);

void zz_arm64_writer_put_b_cond_imm(ZzWriter *self, arm64_cc cc, zsize imm);

void zz_arm64_writer_put_ldr_reg_reg_offset(ZzWriter *self, arm64_reg dst_reg,
                                   arm64_reg src_reg, zsize src_offset);

void zz_arm64_writer_put_str_reg_reg_offset(ZzWriter *self, arm64_reg src_reg,
                                   arm64_reg dst_reg, zsize dst_offset);

void zz_arm64_writer_put_sub_reg_reg_imm(ZzWriter *self, arm64_reg dst_reg,
                                arm64_reg left_reg, zsize right_value);

void zz_arm64_writer_put_add_reg_reg_imm(ZzWriter *self, arm64_reg dst_reg,
                                arm64_reg left_reg, zsize right_value);

void zz_arm64_writer_put_ldr_reg_imm(ZzWriter *self, arm64_reg reg, zsize imm);

void zz_arm64_writer_put_br_reg(ZzWriter *self, arm64_reg reg);


void zz_arm64_writer_put_blr_reg(ZzWriter *self, arm64_reg reg);

void zz_arm64_writer_put_bytes(ZzWriter *self, zbyte *data, zuint data_size);

void zz_arm64_writer_put_instruction(ZzWriter *self, zuint32 insn);


void zz_arm64_writer_put_b_imm(ZzWriter *self, zsize imm);

#endif