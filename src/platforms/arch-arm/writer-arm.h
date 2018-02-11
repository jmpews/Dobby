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

#define MAX_INSN_SIZE 256
typedef struct _ZzARMAssemblerWriter {
    ZzARMInstruction *insns[MAX_INSN_SIZE];
    zz_size_t insn_size;
    zz_addr_t w_start_address;
    zz_addr_t w_current_address;
    zz_addr_t start_pc;
    zz_addr_t current_pc;
    zz_size_t size;
} ZzARMAssemblerWriter;

ZzARMAssemblerWriter *zz_arm_writer_new();
void zz_arm_writer_init(ZzARMAssemblerWriter *self, zz_ptr_t data_ptr, zz_addr_t target_ptr);
void zz_arm_writer_reset(ZzARMAssemblerWriter *self, zz_ptr_t data_ptr, zz_addr_t target_ptr);
void zz_arm_writer_free(ZzARMAssemblerWriter *self);
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

void zz_arm_writer_put_ldr_reg_reg_imm_index(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg,
                                             int32_t imm, bool index);

void zz_arm_writer_put_ldr_reg_reg_imm_A1(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, uint32_t imm,
                                          bool P, bool U, bool W);

void zz_arm_writer_put_ldr_reg_address(ZzARMAssemblerWriter *self, ZzARMReg reg, zz_addr_t address);

void zz_arm_writer_put_add_reg_reg_imm(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, uint32_t imm);

void zz_arm_writer_put_sub_reg_reg_imm(ZzARMAssemblerWriter *self, ZzARMReg dst_reg, ZzARMReg src_reg, uint32_t imm);

void zz_arm_writer_put_push_reg(ZzARMAssemblerWriter *self, ZzARMReg reg);

void zz_arm_writer_put_pop_reg(ZzARMAssemblerWriter *self, ZzARMReg reg);

#endif