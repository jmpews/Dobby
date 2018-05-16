#ifndef platforms_arch_arm_writer_arm_h
#define platforms_arch_arm_writer_arm_h

#include <string.h>

#include "hookzz.h"
#include "zkit.h"

#include "macros.h"
#include "memhelper.h"
#include "writer.h"

#include "instructions.h"
#include "reader-arm.h"
#include "regs-arm.h"
#include "writer-arm.h"

#define MAX_INSN_SIZE 256
typedef struct _ARMAssemblerWriter
{
    ARMInstruction *insnCTXs[MAX_INSN_SIZE];
    zz_size_t insnCTXs_count;
    zz_addr_t start_pc;
    zz_addr_t insns_buffer;
    zz_size_t insns_size;
} ARMAssemblerWriter;

ARMAssemblerWriter *arm_writer_new();
void arm_writer_init(ARMAssemblerWriter *self, zz_addr_t insns_buffer, zz_addr_t target_ptr);
void arm_writer_reset(ARMAssemblerWriter *self, zz_addr_t insns_buffer, zz_addr_t target_ptr);
void arm_writer_free(ARMAssemblerWriter *self);
zz_size_t arm_writer_near_jump_range_size();

// ------- user custom -------

void arm_writer_put_ldr_b_reg_address(ARMAssemblerWriter *self, ARMReg reg, zz_addr_t address);
void arm_writer_put_bx_to_thumb(ARMAssemblerWriter *self);

// ------- architecture default -------

void arm_writer_put_bytes(ARMAssemblerWriter *self, char *data, zz_size_t data_size);

void arm_writer_put_instruction(ARMAssemblerWriter *self, uint32_t insn);

void arm_writer_put_b_imm(ARMAssemblerWriter *self, uint32_t imm);

void arm_writer_put_bx_reg(ARMAssemblerWriter *self, ARMReg reg);

void arm_writer_put_nop(ARMAssemblerWriter *self);

void arm_writer_put_ldr_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, int32_t imm);

void arm_writer_put_str_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, int32_t imm);

void arm_writer_put_ldr_reg_imm_literal(ARMAssemblerWriter *self, ARMReg dst_reg, int32_t imm);

void arm_writer_put_ldr_reg_reg_imm_index(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg,
                                          int32_t imm, bool index);

void arm_writer_put_ldr_reg_reg_imm_A1(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, uint32_t imm,
                                       bool P, bool U, bool W);

void arm_writer_put_ldr_reg_address(ARMAssemblerWriter *self, ARMReg reg, zz_addr_t address);

void arm_writer_put_add_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, uint32_t imm);

void arm_writer_put_sub_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, uint32_t imm);

void arm_writer_put_push_reg(ARMAssemblerWriter *self, ARMReg reg);

void arm_writer_put_pop_reg(ARMAssemblerWriter *self, ARMReg reg);

#endif