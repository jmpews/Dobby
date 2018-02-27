#include "writer-thumb.h"

#include <stdlib.h>

ZzThumbAssemblerWriter *zz_thumb_writer_new() {
    ZzThumbAssemblerWriter *writer = (ZzThumbAssemblerWriter *)zz_malloc_with_zero(sizeof(ZzThumbAssemblerWriter));
    writer->w_current_address      = 0;
    writer->w_start_address        = 0;
    writer->current_pc             = 0 + 4;
    writer->start_pc               = 0 + 4;
    writer->size                   = 0;
    writer->insn_size              = 0;
    return writer;
}

void zz_thumb_writer_init(ZzThumbAssemblerWriter *self, zz_ptr_t data_ptr, zz_addr_t target_ptr) {
    zz_thumb_writer_reset(self, data_ptr, target_ptr);
}

void zz_thumb_writer_reset(ZzThumbAssemblerWriter *self, zz_ptr_t data_ptr, zz_addr_t target_ptr) {
    zz_addr_t align_address = (zz_addr_t)data_ptr & ~(zz_addr_t)3;
    self->w_current_address = align_address;
    self->w_start_address   = align_address;
    self->current_pc        = target_ptr + 4;
    self->start_pc          = target_ptr + 4;
    self->size              = 0;

    if (self->insn_size) {
        for (int i = 0; i < self->insn_size; ++i) {
            free(self->insns[i]);
            self->insns[i] = NULL;
        }
    }
    self->insn_size = 0;
}

void zz_thumb_writer_free(ZzThumbAssemblerWriter *self) {
    if (self->insn_size) {
        for (int i = 0; i < self->insn_size; i++) {
            free(self->insns[i]);
            self->insns[i] = NULL;
        }
    }
    free(self);
}

zz_size_t zz_thumb_writer_near_jump_range_size() { return ((1 << 23) << 1); }

// ------- custom -------

void zz_thumb_writer_put_ldr_b_reg_address(ZzThumbAssemblerWriter *self, ZzARMReg reg, zz_addr_t address) {
    ZzARMRegInfo ri;
    zz_arm_register_describe(reg, &ri);

    if ((((zz_addr_t)self->current_pc) % 4)) {
        if (ri.meta <= ZZ_ARM_REG_R7) {
            zz_thumb_writer_put_ldr_reg_imm(self, reg, 0x4);
            zz_thumb_writer_put_nop(self);
        } else {
            zz_thumb_writer_put_ldr_reg_imm(self, reg, 0x4);
        }
    } else {
        if (ri.meta <= ZZ_ARM_REG_R7) {
            zz_thumb_writer_put_ldr_reg_imm(self, reg, 0x0);
        } else {
            zz_thumb_writer_put_ldr_reg_imm(self, reg, 0x4);
            zz_thumb_writer_put_nop(self);
        }
    }

    zz_thumb_writer_put_b_imm(self, 0x2);
    zz_thumb_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
    return;
}

void zz_thumb_writer_put_ldr_reg_address(ZzThumbAssemblerWriter *self, ZzARMReg reg, zz_addr_t address) {
    ZzARMRegInfo ri;
    zz_arm_register_describe(reg, &ri);

    if ((((zz_addr_t)self->current_pc) % 4)) {
        if (ri.meta <= ZZ_ARM_REG_R7) {
            zz_thumb_writer_put_ldr_reg_imm(self, reg, 0x0);
        } else {
            zz_thumb_writer_put_ldr_reg_imm(self, reg, 0x4);
            zz_thumb_writer_put_nop(self);
        }
    } else {
        zz_thumb_writer_put_ldr_reg_imm(self, reg, 0x0);
        if (ri.meta <= ZZ_ARM_REG_R7)
            zz_thumb_writer_put_nop(self);
    }

    zz_thumb_writer_put_bytes(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
    return;
}

// ------- architecture default -------
void zz_thumb_writer_put_nop(ZzThumbAssemblerWriter *self) {
    zz_thumb_writer_put_instruction(self, 0x46c0);
    return;
}

void zz_thumb_writer_put_bytes(ZzThumbAssemblerWriter *self, char *data, zz_size_t data_size) {
    memcpy((zz_ptr_t)self->w_current_address, data, data_size);
    self->w_current_address = self->w_current_address + data_size;
    self->current_pc += data_size;
    self->size += data_size;

    ZzARMInstruction *arm_insn     = (ZzARMInstruction *)zz_malloc_with_zero(sizeof(ZzARMInstruction));
    arm_insn->pc                   = self->current_pc - data_size;
    arm_insn->address              = self->w_current_address - data_size;
    arm_insn->size                 = data_size;
    arm_insn->insn                 = 0;
    arm_insn->insn1                = 0;
    arm_insn->insn2                = 0;
    arm_insn->type                 = UNKOWN_INSN;
    self->insns[self->insn_size++] = arm_insn;
    return;
}

void zz_thumb_writer_put_instruction(ZzThumbAssemblerWriter *self, uint16_t insn) {
    *(uint16_t *)(self->w_current_address) = insn;
    self->w_current_address                = self->w_current_address + sizeof(uint16_t);
    self->current_pc += 2;
    self->size += 2;

    ZzARMInstruction *arm_insn     = (ZzARMInstruction *)zz_malloc_with_zero(sizeof(ZzARMInstruction));
    arm_insn->pc                   = self->current_pc - 2;
    arm_insn->address              = self->w_current_address - 2;
    arm_insn->size                 = 2;
    arm_insn->insn                 = 0;
    arm_insn->insn1                = insn;
    arm_insn->insn2                = 0;
    arm_insn->type                 = THUMB_INSN;
    self->insns[self->insn_size++] = arm_insn;
    return;
}

void zz_thumb_writer_put_b_imm(ZzThumbAssemblerWriter *self, uint32_t imm) {

    zz_thumb_writer_put_instruction(self, 0xe000 | ((imm / 2) & ZZ_INT11_MASK));
    return;
}

void zz_thumb_writer_put_bx_reg(ZzThumbAssemblerWriter *self, ZzARMReg reg) {
    ZzARMRegInfo ri;

    zz_arm_register_describe(reg, &ri);

    if ((((zz_addr_t)self->current_pc) % 4)) {
        zz_thumb_writer_put_nop(self);
    }

    zz_thumb_writer_put_instruction(self, 0x4700 | (ri.index << 3));
    zz_thumb_writer_put_nop(self);
    return;
}

void zz_thumb_writer_put_blx_reg(ZzThumbAssemblerWriter *self, ZzARMReg reg) {
    ZzARMRegInfo ri;

    zz_arm_register_describe(reg, &ri);

    zz_thumb_writer_put_instruction(self, 0x4780 | (ri.index << 3));
    return;
}

// A8.8.18
void zz_thumb_writer_put_branch_imm(ZzThumbAssemblerWriter *self, uint32_t imm, bool link, bool thumb) {
    union {
        int32_t i;
        uint32_t u;
    } distance;
    uint16_t s, j1, j2, imm10, imm11;

    distance.i = (int32_t)(imm) / 2;

    s  = (distance.u >> 31) & 1;
    j1 = (~((distance.u >> 22) ^ s)) & 1;
    j2 = (~((distance.u >> 21) ^ s)) & 1;

    imm10 = (distance.u >> 11) & ZZ_INT10_MASK;
    imm11 = distance.u & ZZ_INT11_MASK;

    zz_thumb_writer_put_instruction(self, 0xf000 | (s << 10) | imm10);
    zz_thumb_writer_put_instruction(self, 0x8000 | (link << 14) | (j1 << 13) | (thumb << 12) | (j2 << 11) | imm11);
    return;
}

void zz_thumb_writer_put_bl_imm(ZzThumbAssemblerWriter *self, uint32_t imm) {
    zz_thumb_writer_put_branch_imm(self, imm, TRUE, TRUE);
    return;
}

void zz_thumb_writer_put_blx_imm(ZzThumbAssemblerWriter *self, uint32_t imm) {
    zz_thumb_writer_put_branch_imm(self, imm, TRUE, FALSE);
    return;
}

void zz_thumb_writer_put_b_imm32(ZzThumbAssemblerWriter *self, uint32_t imm) {
    zz_thumb_writer_put_branch_imm(self, imm, FALSE, TRUE);
    return;
}

// PAGE: A8-410
// A8.8.64 LDR (literal)
void zz_thumb_writer_put_ldr_reg_imm(ZzThumbAssemblerWriter *self, ZzARMReg reg, int32_t imm) {
    ZzARMRegInfo ri;

    zz_arm_register_describe(reg, &ri);

    if (ri.meta <= ZZ_ARM_REG_R7 && imm >= 0 && imm < ((1 << 8) << 2)) {

        zz_thumb_writer_put_instruction(self, 0x4800 | (ri.index << 8) | ((imm / 4) & ZZ_INT8_MASK));
    } else if (imm < (1 << 12)) {
        bool add = 0;
        if (imm >= 0)
            add = 1;
        zz_thumb_writer_put_instruction(self, 0xf85f | (add << 7));
        zz_thumb_writer_put_instruction(self, (ri.index << 12) | ABS(imm));
    }
    return;
}

bool zz_thumb_writer_put_transfer_reg_reg_offset_T1(ZzThumbAssemblerWriter *self, ZzThumbMemoryOperation operation,
                                                    ZzARMReg left_reg, ZzARMReg right_reg, int32_t right_offset) {
    ZzARMRegInfo lr, rr;

    zz_arm_register_describe(left_reg, &lr);
    zz_arm_register_describe(right_reg, &rr);

    uint16_t insn;

    if (right_offset < 0)
        return FALSE;

    if (lr.meta <= ZZ_ARM_REG_R7 && rr.meta <= ZZ_ARM_REG_R7 && right_offset < ((1 << 5) << 2)) {
        insn = 0x6000 | (right_offset / 4) << 6 | (rr.index << 3) | lr.index;
        if (operation == ZZ_THUMB_MEMORY_LOAD)
            insn |= 0x0800;
        zz_thumb_writer_put_instruction(self, insn);
        return TRUE;
    }
    return FALSE;
}

bool zz_thumb_writer_put_transfer_reg_reg_offset_T2(ZzThumbAssemblerWriter *self, ZzThumbMemoryOperation operation,
                                                    ZzARMReg left_reg, ZzARMReg right_reg, int32_t right_offset) {
    ZzARMRegInfo lr, rr;

    zz_arm_register_describe(left_reg, &lr);
    zz_arm_register_describe(right_reg, &rr);

    uint16_t insn;

    if (right_offset < 0)
        return FALSE;

    if (rr.meta == ZZ_ARM_REG_SP && lr.meta <= ZZ_ARM_REG_R7 && right_offset < ((1 << 8) << 2)) {
        insn = 0x9000 | (lr.index << 8) | (right_offset / 4);
        if (operation == ZZ_THUMB_MEMORY_LOAD)
            insn |= 0x0800;
        zz_thumb_writer_put_instruction(self, insn);
        return TRUE;
    }
    return FALSE;
}

bool zz_thumb_writer_put_transfer_reg_reg_offset_T3(ZzThumbAssemblerWriter *self, ZzThumbMemoryOperation operation,
                                                    ZzARMReg left_reg, ZzARMReg right_reg, int32_t right_offset) {
    ZzARMRegInfo lr, rr;

    zz_arm_register_describe(left_reg, &lr);
    zz_arm_register_describe(right_reg, &rr);

    uint16_t insn;

    if (right_offset < 0)
        return FALSE;

    if (right_offset < (1 << 12)) {
        if (rr.meta == ZZ_ARM_REG_PC) {
            zz_thumb_writer_put_ldr_reg_imm(self, left_reg, right_offset);
        }
        zz_thumb_writer_put_instruction(self,
                                        0xf8c0 | ((operation == ZZ_THUMB_MEMORY_LOAD) ? 0x0010 : 0x0000) | rr.index);
        zz_thumb_writer_put_instruction(self, (lr.index << 12) | right_offset);

        return TRUE;
    }
    return FALSE;
}

bool zz_thumb_writer_put_transfer_reg_reg_offset_T4(ZzThumbAssemblerWriter *self, ZzThumbMemoryOperation operation,
                                                    ZzARMReg left_reg, ZzARMReg right_reg, int32_t right_offset,
                                                    bool index, bool wback) {
    ZzARMRegInfo lr, rr;

    zz_arm_register_describe(left_reg, &lr);
    zz_arm_register_describe(right_reg, &rr);

    uint16_t insn;

    if (ABS(right_offset) < (1 << 8)) {
        if (rr.meta == ZZ_ARM_REG_PC) {
            zz_thumb_writer_put_ldr_reg_imm(self, left_reg, right_offset);
        } else {
            bool add = 0;
            if (right_offset > 0)
                add = 1;
            zz_thumb_writer_put_instruction(self, 0xf840 | ((operation == ZZ_THUMB_MEMORY_LOAD) ? 0x0010 : 0x0000) |
                                                      rr.index);
            zz_thumb_writer_put_instruction(self, 0x0800 | (lr.index << 12) | (index << 10) | (add << 9) |
                                                      (wback << 8) | (ABS(right_offset)));
            return TRUE;
        }
    }
    return FALSE;
}

// PAGE: A8-406
// PAGE: A8.8.203 STR (immediate, Thumb)
static void zz_thumb_writer_put_transfer_reg_reg_offset(ZzThumbAssemblerWriter *self, ZzThumbMemoryOperation operation,
                                                        ZzARMReg left_reg, ZzARMReg right_reg, int32_t right_offset) {
    if (zz_thumb_writer_put_transfer_reg_reg_offset_T1(self, operation, left_reg, right_reg, right_offset))
        return;

    if (zz_thumb_writer_put_transfer_reg_reg_offset_T2(self, operation, left_reg, right_reg, right_offset))
        return;

    if (zz_thumb_writer_put_transfer_reg_reg_offset_T3(self, operation, left_reg, right_reg, right_offset))
        return;
    if (zz_thumb_writer_put_transfer_reg_reg_offset_T4(self, operation, left_reg, right_reg, right_offset, 1, 0))
        return;
    return;
}

void zz_thumb_writer_put_ldr_reg_reg_offset(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg,
                                            int32_t src_offset) {
    zz_thumb_writer_put_transfer_reg_reg_offset(self, ZZ_THUMB_MEMORY_LOAD, dst_reg, src_reg, src_offset);
    return;
}

void zz_thumb_writer_put_str_reg_reg_offset(ZzThumbAssemblerWriter *self, ZzARMReg src_reg, ZzARMReg dst_reg,
                                            int32_t dst_offset) {
    zz_thumb_writer_put_transfer_reg_reg_offset(self, ZZ_THUMB_MEMORY_STORE, src_reg, dst_reg, dst_offset);
    return;
}

void zz_thumb_writer_put_ldr_index_reg_reg_offset(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg,
                                                  int32_t src_offset, bool index) {
    zz_thumb_writer_put_transfer_reg_reg_offset_T4(self, ZZ_THUMB_MEMORY_LOAD, dst_reg, src_reg, src_offset, index, 1);
    return;
}

void zz_thumb_writer_put_str_index_reg_reg_offset(ZzThumbAssemblerWriter *self, ZzARMReg src_reg, ZzARMReg dst_reg,
                                                  int32_t dst_offset, bool index) {
    zz_thumb_writer_put_transfer_reg_reg_offset_T4(self, ZZ_THUMB_MEMORY_STORE, src_reg, dst_reg, dst_offset, index, 1);
    return;
}

void zz_thumb_writer_put_str_reg_reg(ZzThumbAssemblerWriter *self, ZzARMReg src_reg, ZzARMReg dst_reg) {
    zz_thumb_writer_put_str_reg_reg_offset(self, src_reg, dst_reg, 0);
    return;
}

void zz_thumb_writer_put_ldr_reg_reg(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg) {
    zz_thumb_writer_put_ldr_reg_reg_offset(self, dst_reg, src_reg, 0);
    return;
}

void zz_thumb_writer_put_add_reg_imm(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, int32_t imm) {
    ZzARMRegInfo dst;
    uint16_t sign_mask, insn;

    zz_arm_register_describe(dst_reg, &dst);

    sign_mask = 0x0000;
    if (dst.meta == ZZ_ARM_REG_SP) {

        if (imm < 0)
            sign_mask = 0x0080;

        insn = 0xb000 | sign_mask | ABS(imm / 4);
    } else {
        if (imm < 0)
            sign_mask = 0x0800;

        insn = 0x3000 | sign_mask | (dst.index << 8) | ABS(imm);
    }

    zz_thumb_writer_put_instruction(self, insn);
    return;
}

void zz_thumb_writer_put_sub_reg_imm(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, int32_t imm) {
    zz_thumb_writer_put_add_reg_imm(self, dst_reg, -imm);
    return;
}

void zz_thumb_writer_put_add_reg_reg_imm(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg left_reg,
                                         int32_t right_value) {
    ZzARMRegInfo dst, left;
    uint16_t insn;

    zz_arm_register_describe(dst_reg, &dst);
    zz_arm_register_describe(left_reg, &left);

    if (left.meta == dst.meta) {
        return zz_thumb_writer_put_add_reg_imm(self, dst_reg, right_value);
    }

    if (dst.meta <= ZZ_ARM_REG_R7 && left.meta <= ZZ_ARM_REG_R7 && ABS(right_value) < (1 << 3)) {
        uint32_t sign_mask = 0;

        if (right_value < 0)
            sign_mask = 1 << 9;

        insn = 0x1c00 | sign_mask | (ABS(right_value) << 6) | (left.index << 3) | dst.index;
        zz_thumb_writer_put_instruction(self, insn);
    } else if ((left.meta == ZZ_ARM_REG_SP || left.meta == ZZ_ARM_REG_PC) && dst.meta <= ZZ_ARM_REG_R7 &&
               right_value > 0 && (right_value % 4 == 0) && right_value < (1 << 8)) {
        uint16_t base_mask;

        if (left.meta == ZZ_ARM_REG_SP)
            base_mask = 0x0800;
        else
            base_mask = 0x0000;

        insn = 0xa000 | base_mask | (dst.index << 8) | (right_value / 4);
        zz_thumb_writer_put_instruction(self, insn);
    } else {
        uint16_t insn1, insn2;
        zz_size_t i, imm3, imm8;
        i    = (ABS(right_value) >> (3 + 8)) & 0x1;
        imm3 = (ABS(right_value) >> 8) & 0b111;
        imm8 = ABS(right_value) & 0b11111111;

        // A8-708, sub
        // A8-306 add
        if (right_value < 0)
            zz_thumb_writer_put_instruction(self, 0b1111001010100000 | i << 10 | left.index);
        else
            zz_thumb_writer_put_instruction(self, 0b1111001000000000 | i << 10 | left.index);
        zz_thumb_writer_put_instruction(self, 0b0 | imm3 << 12 | dst.index << 8 | imm8);
    }

    return;
}

void zz_thumb_writer_put_sub_reg_reg_imm(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg left_reg,
                                         int32_t right_value) {
    zz_thumb_writer_put_add_reg_reg_imm(self, dst_reg, left_reg, -right_value);
    return;
}

void zz_thumb_writer_put_push_reg(ZzThumbAssemblerWriter *self, ZzARMReg reg) {
    ZzARMRegInfo ri;
    zz_arm_register_describe(reg, &ri);

    uint16_t M, register_list;
    M = 0;

    zz_thumb_writer_put_instruction(self, 0b1011010000000000 | M << 8 | 1 << ri.index);
    return;
}

void zz_thumb_writer_put_pop_reg(ZzThumbAssemblerWriter *self, ZzARMReg reg) {
    ZzARMRegInfo ri;
    zz_arm_register_describe(reg, &ri);

    uint16_t P, register_list;
    P = 0;

    zz_thumb_writer_put_instruction(self, 0b1011110000000000 | P << 8 | 1 << ri.index);
    return;
}

void zz_thumb_writer_put_add_reg_reg_reg(ZzThumbAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg left_reg,
                                         ZzARMReg right_reg) {
    ZzARMRegInfo dst, left, right;
    zz_arm_register_describe(dst_reg, &dst);
    zz_arm_register_describe(left_reg, &left);
    zz_arm_register_describe(right_reg, &right);

    uint16_t Rm_ndx, Rn_ndx, Rd_ndx;
    Rd_ndx = dst.index;
    Rm_ndx = right.index;
    Rn_ndx = left.index;

    zz_thumb_writer_put_instruction(self, 0b0001100000000000 | Rm_ndx << 6 | Rn_ndx << 3 | Rd_ndx);
    return;
}