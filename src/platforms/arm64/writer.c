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

#include "writer.h"
#include <string.h>

// ARM Architecture Reference Manual ARMV8
// C2.1 Understanding the A64 instruction descriptions
// C2.1.3 The instruction encoding or encodings

ZzWriter *ZzNewWriter(zpointer address)
{
    ZzWriter *writer = (ZzWriter *)malloc(sizeof(ZzWriter));
    writer->codedata = address;
    writer->base = address;
    writer->pc = address;
    writer->size = 0;
    return writer;
}

// ATTENTION!!!
// the instructions size must equal to `JMP_METHOD_SIZE`
void WriterPutAbsJmp(ZzWriter *self, zpointer target_addr)
{
    writer_put_ldr_reg_imm(self, ARM64_REG_X17, (zuint)0x8);
    writer_put_br_reg(self, ARM64_REG_X17);
    writer_put_bytes(self, (zpointer)&target_addr, sizeof(target_addr));
}

void WriterPutRetAbsJmp(ZzWriter *self, zpointer target_addr)
{
    writer_put_ldr_reg_address(self, ARM64_REG_X17, (zaddr)target_addr);
    writer_put_blr_reg(self, ARM64_REG_X17);
}

// NOUSE:
void writer_put_ldr_br_b_reg_address(ZzWriter *self, arm64_reg reg,
                                     zaddr address)
{
    writer_put_ldr_reg_imm(self, reg, (zuint)0xc);
    writer_put_br_reg(self, reg);
    writer_put_b_imm(self, (zaddr)0xc);
    writer_put_bytes(self, (zpointer)&address, sizeof(address));
}

void writer_put_ldr_reg_address(ZzWriter *self, arm64_reg reg, zaddr address)
{
    writer_put_ldr_reg_imm(self, reg, (zuint)0x8);
    writer_put_b_imm(self, (zaddr)0xc);
    writer_put_bytes(self, (zpointer)&address, sizeof(address));
}

void writer_put_ldr_reg_imm(ZzWriter *self, arm64_reg reg, zuint imm)
{
    ZzArm64RegInfo ri;
    uint32_t ins_bytes = 0;

    writer_describe_reg(reg, &ri);

    ins_bytes = 0x58000000 | ri.index;

    writer_put_instruction(self, ins_bytes | ((imm >> 2) << 5));
}

// PAGE: C6-871
// ARM Architecture Reference Manual ARMV8
// C6 A64 Base Instruction Descriptions
// C6.2 Alphabetical list of A64 base instructions
void writer_put_str_reg_reg_offset(ZzWriter *self, arm64_reg src_reg,
                                   arm64_reg dst_reg, zsize dst_offset)
{
    ZzArm64RegInfo rs, rd;
    zuint size, v, opc;

    writer_describe_reg(src_reg, &rs);
    writer_describe_reg(dst_reg, &rd);

    opc = 0;
    if (rs.is_integer)
    {
        size = (rs.width == 64) ? 3 : 2;
        v = 0;
    }

    writer_put_instruction(self,
                           0x39000000 | (size << 30) | (v << 26) | (opc << 22) |
                               (((zuint)dst_offset / (rs.width / 8)) << 10) |
                               (rd.index << 5) | rs.index);
}

void writer_put_ldr_reg_reg_offset(ZzWriter *self, arm64_reg dst_reg,
                                   arm64_reg src_reg, zsize src_offset)
{
    ZzArm64RegInfo rs, rd;
    zuint size, v, opc;

    writer_describe_reg(dst_reg, &rd);
    writer_describe_reg(src_reg, &rs);

    opc = 1;
    if (rd.is_integer)
    {
        size = (rd.width == 64) ? 3 : 2;
        v = 0;
    }

    writer_put_instruction(self,
                           0x39000000 | (size << 30) | (v << 26) | (opc << 22) |
                               (((zuint)src_offset / (rd.width / 8)) << 10) |
                               (rs.index << 5) | rd.index);
}

void writer_put_b_cond_imm(ZzWriter *self, arm64_cc cc, zuint imm)
{
    uint32_t ins_bytes = 0;
    ins_bytes = ins_bytes | 0x54000000 | (cc - 1);
    ins_bytes = ins_bytes | (imm >> 2) << 5;
    writer_put_instruction(self, ins_bytes);
}

void writer_put_br_reg(ZzWriter *self, arm64_reg reg)
{
    ZzArm64RegInfo ri;
    writer_describe_reg(reg, &ri);

    writer_put_instruction(self, 0xd61f0000 | (ri.index << 5));
}

void writer_put_blr_reg(ZzWriter *self, arm64_reg reg)
{
    ZzArm64RegInfo ri;
    writer_describe_reg(reg, &ri);

    writer_put_instruction(self, 0xd63f0000 | (ri.index << 5));
}

void writer_put_b_imm(ZzWriter *self, zuint imm)
{
    // zaddr offset = address - (zaddr)self->pc;
    writer_put_instruction(self, 0x14000000 | ((imm / 4) & 0x03ffffff));
}

void writer_put_add_reg_reg_imm(ZzWriter *self, arm64_reg dst_reg,
                                arm64_reg left_reg, zsize right_value)
{
    ZzArm64RegInfo rd, rl;

    writer_describe_reg(dst_reg, &rd);
    writer_describe_reg(left_reg, &rl);

    // PAGE: C2-148
    // ARM Architecture Reference Manual ARMV8
    // C2.1 Understanding the A64 instruction descriptions
    // C2.1.3 The instruction encoding or encodings
    // sf
    writer_put_instruction(self, (1 << 31) | 0x11000000 | rd.index | (rl.index << 5) | (right_value << 10));
}

void writer_put_sub_reg_reg_imm(ZzWriter *self, arm64_reg dst_reg,
                                arm64_reg left_reg, zsize right_value)
{
    ZzArm64RegInfo rd, rl;

    writer_describe_reg(dst_reg, &rd);
    writer_describe_reg(left_reg, &rl);

    // `sf` same as `add`
    writer_put_instruction(self, (1 << 31) | 0x51000000 | rd.index | (rl.index << 5) | (right_value << 10));
}

void writer_put_bytes(ZzWriter *self, zbyte *data, zuint data_size)
{
    memcpy(self->codedata, data, data_size);
    self->codedata = (zpointer)self->codedata + data_size;
    self->pc += data_size;
    self->size += data_size;
}

void writer_put_instruction(ZzWriter *self, uint32_t insn)
{
    *(uint32_t *)(self->codedata) = insn;
    self->codedata = (zpointer)self->codedata + sizeof(uint32_t);
    self->pc += 4;
    self->size += 4;
}

// TODO:
typedef enum _ZzReg {
    //   zzfp = 29,
    //   zzlr = 30,
    //   zzsp = 31,
    zzx0 = 0,
    zzx1,
    zzx2,
    zzx3,
    zzx4,
    zzx5,
    zzx6,
    zzx7,
    zzx8,
    zzx9,
    zzx10,
    zzx11,
    zzx12,
    zzx13,
    zzx14,
    zzx15,
    zzx16,
    zzx17,
    zzx18,
    zzx19,
    zzx20,
    zzx21,
    zzx22,
    zzx23,
    zzx24,
    zzx25,
    zzx26,
    zzx27,
    zzx28,
    zzx29,
    zzx30,
    zzx31,
    zzfp = zzx29,
    zzlr = zzx30,
    zzsp = zzx31
} ZzReg;

void writer_describe_reg(arm64_reg reg, ZzArm64RegInfo *ri)
{
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
    {
        ri->is_integer = true;
        ri->width = 64;
        ri->meta = zzx0 + (reg - ARM64_REG_X0);
    }
    else if (reg == ARM64_REG_X29 || reg == ARM64_REG_FP)
    {
        ri->is_integer = true;
        ri->width = 64;
        ri->meta = zzx29;
    }
    else if (reg == ARM64_REG_X30 || reg == ARM64_REG_LR)
    {
        ri->is_integer = true;
        ri->width = 64;
        ri->meta = zzx30;
    }
    else if (reg == ARM64_REG_SP)
    {
        ri->is_integer = true;
        ri->width = 64;
        ri->meta = zzx31;
    }
    else
    {
        Serror("error at writer_describe_reg");
        exit(1);
        ri->index = 0;
    }
    ri->index = ri->meta - zzx0;
}
