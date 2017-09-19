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
 *    See the License for the specific lanzuage governing permissions and
 *    limitations under the License.
 */

#include "writer-thumb.h"

// ATTENTION !!!:
// 写 writer 部分, 需要参考, `Instrcution Set Encoding` 部分
// `witer` REF: `Instruction Set Encoding`

ZzThumbWriter *zz_thumb_writer_new(zpointer data_ptr) {
    ZzThumbWriter *writer = (ZzThumbWriter *)malloc(sizeof(ZzThumbWriter));
    writer->codedata = data_ptr;
    writer->base = data_ptr;
    writer->pc = data_ptr;
    writer->size = 0;
    return writer;
}

void zz_thumb_writer_init(ZzThumbWriter *self, zpointer data_ptr) {
    zz_thumb_writer_reset(self, data_ptr);
}

void zz_thumb_writer_reset(ZzThumbWriter *self, zpointer data_ptr) {
    self->codedata = data_ptr;
    self->base = data_ptr;
    self->pc = data_ptr;
    self->size = 0;
}
// ------- user custom -------

void zz_thumb_writer_put_add_sub_ldr_reg_reg_offset(ZzThumbWriter *self, arm_reg dst_reg,
                                                    arm_reg src_reg, zint32 src_offset) {
    zz_thumb_writer_put_add_reg_imm(self, src_reg, src_offset);
    zz_thumb_writer_put_transfer_reg_reg_offset(self, ZZ_THUMB_MEMORY_LOAD, dst_reg, src_reg, 0);
    zz_thumb_writer_put_sub_reg_imm(self, src_reg, src_offset);
}

void zz_thumb_writer_put_add_sub_str_reg_reg_offset(ZzThumbWriter *self, arm_reg src_reg,
                                                    arm_reg dst_reg, zint32 dst_offset) {
    zz_thumb_writer_put_add_reg_imm(self, src_reg, dst_offset);
    zz_thumb_writer_put_transfer_reg_reg_offset(self, ZZ_THUMB_MEMORY_STORE, src_reg, dst_reg, 0);
    zz_thumb_writer_put_sub_reg_imm(self, src_reg, dst_offset);
}

// ------- architecture default -------
void zz_thumb_writer_put_bytes(ZzThumbWriter *self, zbyte *data, zuint data_size) {
    memcpy(self->codedata, data, data_size);
    self->codedata = (zpointer)self->codedata + data_size;
    self->pc += data_size;
    self->size += data_size;
}

void zz_thumb_writer_put_instruction(ZzThumbWriter *self, uint16_t insn) {
    *(uint16_t *)(self->codedata) = insn;
    self->codedata = (zpointer)self->codedata + sizeof(uint16_t);
    self->pc += 2;
    self->size += 2;
}

void zz_thumb_writer_put_b_imm(ZzThumbWriter *self, zuint32 imm) {
    zz_thumb_writer_put_instruction(self, 0xe000 | ((imm / 2) & ZZ_INT11_MASK));
}

void zz_thumb_writer_put_bx_reg(ZzThumbWriter *self, arm_reg reg) {
    ZzArmRegInfo ri;

    zz_arm_register_describe(reg, &ri);

    zz_thumb_writer_put_instruction(self, 0x4700 | (ri.index << 3));
}

void zz_thumb_writer_put_blx_reg(ZzThumbWriter *self, arm_reg reg) {
    ZzArmRegInfo ri;

    zz_arm_register_describe(reg, &ri);

    zz_thumb_writer_put_instruction(self, 0x4780 | (ri.index << 3));
}

// A8.8.18
void zz_thumb_writer_put_branch_imm(ZzThumbWriter *self, zuint32 imm, zbool link, zbool thumb) {
    union {
        zint32 i;
        zuint32 u;
    } distance;
    zuint16 s, j1, j2, imm10, imm11;

    distance.i = (zint32)(imm) / 2;

    s = (distance.u >> 31) & 1;
    j1 = (~((distance.u >> 22) ^ s)) & 1;
    j2 = (~((distance.u >> 21) ^ s)) & 1;

    imm10 = (distance.u >> 11) & ZZ_INT10_MASK;
    imm11 = distance.u & ZZ_INT11_MASK;

    zz_thumb_writer_put_instruction(self, 0xf000 | (s << 10) | imm10);
    zz_thumb_writer_put_instruction(self, 0x8000 | (link << 14) | (j1 << 13) | (thumb << 12) |
                                              (j2 << 11) | imm11);
}

void zz_thumb_writer_put_bl_imm(ZzThumbWriter *self, zuint32 imm) {
    zz_thumb_writer_put_branch_imm(self, imm, true, true);
}

void zz_thumb_writer_put_blx_imm(ZzThumbWriter *self, zuint32 imm) {
    zz_thumb_writer_put_branch_imm(self, imm, true, false);
}

void zz_thumb_writer_put_b_imm32(ZzThumbWriter *self, zuint32 imm) {
    zz_thumb_writer_put_branch_imm(self, imm, false, true);
}

// PAGE: A8-410
// A8.8.64 LDR (literal)
void zz_thumb_writer_put_ldr_reg_imm(ZzThumbWriter *self, arm_reg reg, zint32 imm) {
    ZzArmRegInfo ri;

    zz_arm_register_describe(reg, &ri);

    if (ri.meta <= ZZ_ARM_R7) {
        zz_thumb_writer_put_instruction(self,
                                        0x4800 | (ri.index << 8) | ((imm / 4) & ZZ_INT8_MASK));
    } else {
        zbool add = true;
        zz_thumb_writer_put_instruction(self, 0xf85f | (add << 7));
        zz_thumb_writer_put_instruction(self, (ri.index << 12) | imm);
    }
}

void zz_thumb_writer_put_ldr_reg_address(ZzThumbWriter *self, arm_reg reg, zaddr address) {
    zz_thumb_writer_put_ldr_reg_imm(self, reg, 2);
    zz_thumb_writer_put_b_imm(self, 0x2);
    zz_thumb_writer_put_bytes(self, (zpointer)&address, sizeof(zpointer));
}

// PAGE: A8-406
// PAGE: A8.8.203 STR (immediate, Thumb)
static void zz_thumb_writer_put_transfer_reg_reg_offset(ZzThumbWriter *self,
                                                        ZzThumbMemoryOperation operation,
                                                        arm_reg left_reg, arm_reg right_reg,
                                                        zint32 right_offset) {
    ZzArmRegInfo lr, rr;

    zz_arm_register_describe(left_reg, &lr);
    zz_arm_register_describe(right_reg, &rr);

    if (right_offset >= 0) {
        if (lr.meta <= ZZ_ARM_R7 && (rr.meta <= ZZ_ARM_R7 || rr.meta == ZZ_ARM_SP) &&
            ((rr.meta == ZZ_ARM_SP && right_offset <= 1020) ||
             (rr.meta != ZZ_ARM_SP && right_offset <= 124)) &&
            (right_offset % 4) == 0) {
            zuint16 insn;

            if (rr.meta == ZZ_ARM_SP)
                insn = 0x9000 | (lr.index << 8) | (right_offset / 4);
            else
                insn = 0x6000 | (right_offset / 4) << 6 | (rr.index << 3) | lr.index;

            if (operation == ZZ_THUMB_MEMORY_LOAD)
                insn |= 0x0800;

            zz_thumb_writer_put_instruction(self, insn);
        } else {
            if (right_offset > 4095)
                return;
            zz_thumb_writer_put_instruction(
                self, 0xf8c0 | ((operation == ZZ_THUMB_MEMORY_LOAD) ? 0x0010 : 0x0000) | rr.index);
            zz_thumb_writer_put_instruction(self, (lr.index << 12) | right_offset);
        }
    } else {
        zz_thumb_writer_put_instruction(
            self, 0xf840 | ((operation == ZZ_THUMB_MEMORY_LOAD) ? 0x0010 : 0x0000) | rr.index);
        zz_thumb_writer_put_instruction(self, 0x0c00 | (lr.index << 12) |
                                                  (ABS(right_offset) & ZZ_INT8_MASK));
    }
}

void zz_thumb_writer_put_ldr_reg_reg_offset(ZzThumbWriter *self, arm_reg dst_reg, arm_reg src_reg,
                                            zsize src_offset) {
    zz_thumb_writer_put_transfer_reg_reg_offset(self, ZZ_THUMB_MEMORY_LOAD, dst_reg, src_reg,
                                                src_offset);
}

void zz_thumb_writer_put_str_reg_reg_offset(ZzThumbWriter *self, arm_reg src_reg, arm_reg dst_reg,
                                            zsize dst_offset) {
    zz_thumb_writer_put_transfer_reg_reg_offset(self, ZZ_THUMB_MEMORY_STORE, src_reg, dst_reg,
                                                dst_offset);
}
void zz_thumb_writer_put_str_reg_reg(ZzThumbWriter *self, arm_reg src_reg, arm_reg dst_reg) {
    zz_thumb_writer_put_str_reg_reg_offset(self, src_reg, dst_reg, 0);
}

void zz_thumb_writer_put_ldr_reg_reg(ZzThumbWriter *self, arm_reg dst_reg, arm_reg src_reg) {
    zz_thumb_writer_put_ldr_reg_reg_offset(self, dst_reg, src_reg, 0);
}

void zz_thumb_writer_put_add_reg_imm(ZzThumbWriter *self, arm_reg dst_reg, zint32 imm) {
    ZzArmRegInfo dst;
    zuint16 sign_mask, insn;

    zz_arm_register_describe(dst_reg, &dst);

    sign_mask = 0x0000;
    if (dst.meta == ZZ_ARM_SP) {

        if (imm < 0)
            sign_mask = 0x0080;

        insn = 0xb000 | sign_mask | ABS(imm / 4);
    } else {
        if (imm < 0)
            sign_mask = 0x0800;

        insn = 0x3000 | sign_mask | (dst.index << 8) | ABS(imm);
    }

    zz_thumb_writer_put_instruction(self, insn);
}

void zz_thumb_writer_put_sub_reg_imm(ZzThumbWriter *self, arm_reg dst_reg, zint32 imm) {
    zz_thumb_writer_put_add_reg_imm(self, dst_reg, -imm);
}

zsize zz_thumb_writer_near_jump_range_size() { return 16; }