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

#include "zzdeps/zz.h"
#include "writer-arm64.h"

// REF:
// ARM Architecture Reference Manual ARMV8
// C2.1 Understanding the A64 instruction descriptions
// C2.1.3 The instruction encoding or encodings

ZzWriter *ZzWriterNewWriter(zpointer address) {
    ZzWriter *writer = (ZzWriter *) malloc(sizeof(ZzWriter));
    writer->codedata = address;
    writer->base = address;
    writer->pc = address;
    writer->size = 0;
    return writer;
}

void ZzWriterPutAbsJump(ZzWriter *self, zpointer target_addr) // @common-function
{
    zz_arm64_writer_put_ldr_reg_imm(self, ARM64_REG_X17, (zuint) 0x8);
    zz_arm64_writer_put_br_reg(self, ARM64_REG_X17);
    zz_arm64_writer_put_bytes(self, (zpointer) & target_addr, sizeof(target_addr));
}

void ZzWriterPutNearJump(ZzWriter *self, zsize offset) {
    zz_arm64_writer_put_b_imm(self, offset);
}

void ZzWriterPutRetAbsJmp(ZzWriter *self, zpointer target_addr) // @common-function
{
    zz_arm64_writer_put_ldr_reg_address(self, ARM64_REG_X17, (zaddr) target_addr);
    zz_arm64_writer_put_blr_reg(self, ARM64_REG_X17);
}

zsize ZzWriterNearJumpRangeSize() {
    return ((1 << 25) << 2);
}

zsize ZzWriterAbsJumpInstructionLength() {
    return 16;
}

zsize ZzWriterNearJumpInstructionLength() {
    return 4;
}

// NOUSE:
void zz_arm64_writer_put_ldr_br_b_reg_address(ZzWriter *self, arm64_reg reg,
                                     zaddr address) {
    zz_arm64_writer_put_ldr_reg_imm(self, reg, (zuint) 0xc);
    zz_arm64_writer_put_br_reg(self, reg);
    zz_arm64_writer_put_b_imm(self, (zaddr) 0xc);
    zz_arm64_writer_put_bytes(self, (zpointer) & address, sizeof(address));
}

void zz_arm64_writer_put_ldr_reg_address(ZzWriter *self, arm64_reg reg, zaddr address) {
    zz_arm64_writer_put_ldr_reg_imm(self, reg, (zuint) 0x8);
    zz_arm64_writer_put_b_imm(self, (zaddr) 0xc);
    zz_arm64_writer_put_bytes(self, (zpointer) & address, sizeof(address));
}

void zz_arm64_writer_put_ldr_reg_imm(ZzWriter *self, arm64_reg reg, zuint imm) {
    ZzArm64RegInfo ri;
    zuint32 insn_bytes = 0;

    zz_arm64_register_describe(reg, &ri);

    insn_bytes = 0x58000000 | ri.index;

    zz_arm64_writer_put_instruction(self, insn_bytes | ((imm >> 2) << 5));
}

// PAGE: C6-871
// ARM Architecture Reference Manual ARMV8
// C6 A64 Base Instruction Descriptions
// C6.2 Alphabetical list of A64 base instructions
void zz_arm64_writer_put_str_reg_reg_offset(ZzWriter *self, arm64_reg src_reg,
                                   arm64_reg dst_reg, zsize dst_offset) {
    ZzArm64RegInfo rs, rd;
    zuint size = 0, v, opc;

    zz_arm64_register_describe(src_reg, &rs);
    zz_arm64_register_describe(dst_reg, &rd);

    opc = 0;
    if (rs.is_integer) {
        size = (rs.width == 64) ? 3 : 2;
        v = 0;
    }

    zz_arm64_writer_put_instruction(self,
                           0x39000000 | (size << 30) | (v << 26) | (opc << 22) |
                           (((zuint) dst_offset / (rs.width / 8)) << 10) |
                           (rd.index << 5) | rs.index);
}

void zz_arm64_writer_put_ldr_reg_reg_offset(ZzWriter *self, arm64_reg dst_reg,
                                   arm64_reg src_reg, zsize src_offset) {
    ZzArm64RegInfo rs, rd;
    zuint size, v, opc;

    zz_arm64_register_describe(dst_reg, &rd);
    zz_arm64_register_describe(src_reg, &rs);

    opc = 1;
    if (rd.is_integer) {
        size = (rd.width == 64) ? 3 : 2;
        v = 0;
    }

    zz_arm64_writer_put_instruction(self,
                           0x39000000 | (size << 30) | (v << 26) | (opc << 22) |
                           (((zuint) src_offset / (rd.width / 8)) << 10) |
                           (rs.index << 5) | rd.index);
}

void zz_arm64_writer_put_b_cond_imm(ZzWriter *self, arm64_cc cc, zuint imm) {
    zuint32 insn_bytes = 0;
    insn_bytes = insn_bytes | 0x54000000 | (cc - 1);
    insn_bytes = insn_bytes | (imm >> 2) << 5;
    zz_arm64_writer_put_instruction(self, insn_bytes);
}

void zz_arm64_writer_put_br_reg(ZzWriter *self, arm64_reg reg) {
    ZzArm64RegInfo ri;
    zz_arm64_register_describe(reg, &ri);

    zz_arm64_writer_put_instruction(self, 0xd61f0000 | (ri.index << 5));
}

void zz_arm64_writer_put_blr_reg(ZzWriter *self, arm64_reg reg) {
    ZzArm64RegInfo ri;
    zz_arm64_register_describe(reg, &ri);

    zz_arm64_writer_put_instruction(self, 0xd63f0000 | (ri.index << 5));
}

void zz_arm64_writer_put_b_imm(ZzWriter *self, zsize imm) {
    // zaddr offset = address - (zaddr)self->pc;
    zz_arm64_writer_put_instruction(self, 0x14000000 | ((imm / 4) & 0x03ffffff));
}

void zz_arm64_writer_put_add_reg_reg_imm(ZzWriter *self, arm64_reg dst_reg,
                                arm64_reg left_reg, zsize right_value) {
    ZzArm64RegInfo rd, rl;

    zz_arm64_register_describe(dst_reg, &rd);
    zz_arm64_register_describe(left_reg, &rl);

    // PAGE: C2-148
    // ARM Architecture Reference Manual ARMV8
    // C2.1 Understanding the A64 instruction descriptions
    // C2.1.3 The instruction encoding or encodings
    // sf
    zz_arm64_writer_put_instruction(self, (1 << 31) | 0x11000000 | rd.index | (rl.index << 5) | (right_value << 10));
}

void zz_arm64_writer_put_sub_reg_reg_imm(ZzWriter *self, arm64_reg dst_reg,
                                arm64_reg left_reg, zsize right_value) {
    ZzArm64RegInfo rd, rl;

    zz_arm64_register_describe(dst_reg, &rd);
    zz_arm64_register_describe(left_reg, &rl);

    // `sf` same as `add`
    zz_arm64_writer_put_instruction(self, (1 << 31) | 0x51000000 | rd.index | (rl.index << 5) | (right_value << 10));
}

void zz_arm64_writer_put_bytes(ZzWriter *self, zbyte *data, zuint data_size) {
    memcpy(self->codedata, data, data_size);
    self->codedata = (zpointer) self->codedata + data_size;
    self->pc += data_size;
    self->size += data_size;
}

void zz_arm64_writer_put_instruction(ZzWriter *self, zuint32 insn) {
    *(zuint32 * )(self->codedata) = insn;
    self->codedata = (zpointer) self->codedata + sizeof(zuint32);
    self->pc += 4;
    self->size += 4;
}

void zz_arm64_register_describe(arm64_reg reg, ZzArm64RegInfo *ri) {
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        ri->is_integer = true;
        ri->width = 64;
        ri->meta = zzx0 + (reg - ARM64_REG_X0);
    } else if (reg == ARM64_REG_X29 || reg == ARM64_REG_FP) {
        ri->is_integer = true;
        ri->width = 64;
        ri->meta = zzx29;
    } else if (reg == ARM64_REG_X30 || reg == ARM64_REG_LR) {
        ri->is_integer = true;
        ri->width = 64;
        ri->meta = zzx30;
    } else if (reg == ARM64_REG_SP) {
        ri->is_integer = true;
        ri->width = 64;
        ri->meta = zzx31;
    } else {
        Serror("zz_arm64_register_describe error.");
        #if defined(DEBUG_MODE)
            debug_break();
        #endif
        ri->index = 0;
    }
    ri->index = ri->meta - zzx0;
}
