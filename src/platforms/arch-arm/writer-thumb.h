#ifndef platforms_arch_arm_writer_thumb_h
#define platforms_arch_arm_writer_thumb_h

#include "instruction.h"
#include "register-arm.h"

#include "writer-arm.h"

#include "std_kit/std_buffer_array.h"
#include "std_kit/std_kit.h"
#include "std_kit/std_list.h"

typedef ARMAssemblerWriter ThumbAssemblyWriter;

== == == == == == == == == == == == == == == == == == == == == == = ;

// ------- user custom -------

void thumb_writer_put_ldr_b_reg_address(ThumbAssemblyWriter *self, ARMReg reg, zz_addr_t address);

// ------- architecture default -------

ThumbAssemblyWriter *thumb_writer_new();

void thumb_writer_init(ThumbAssemblyWriter *self, zz_addr_t insns_buffer, zz_addr_t target_ptr);

void thumb_writer_reset(ThumbAssemblyWriter *self, zz_addr_t insns_buffer, zz_addr_t target_ptr);

void thumb_writer_free(ThumbAssemblyWriter *self);

zz_size_t thumb_writer_near_jump_range_size();

void thumb_writer_put_nop(ThumbAssemblyWriter *self);

void thumb_writer_put_bytes(ThumbAssemblyWriter *self, char *data, zz_size_t data_size);

void thumb_writer_put_instruction(ThumbAssemblyWriter *self, uint16_t insn);

void thumb_writer_put_b_imm(ThumbAssemblyWriter *self, uint32_t imm);

void thumb_writer_put_bx_reg(ThumbAssemblyWriter *self, ARMReg reg);

void thumb_writer_put_blx_reg(ThumbAssemblyWriter *self, ARMReg reg);

void thumb_writer_put_branch_imm(ThumbAssemblyWriter *self, uint32_t imm, bool link, bool thumb);

void thumb_writer_put_bl_imm(ThumbAssemblyWriter *self, uint32_t imm);

void thumb_writer_put_blx_imm(ThumbAssemblyWriter *self, uint32_t imm);

void thumb_writer_put_b_imm32(ThumbAssemblyWriter *self, uint32_t imm);

void thumb_writer_put_ldr_reg_imm(ThumbAssemblyWriter *self, ARMReg reg, int32_t imm);

void thumb_writer_put_ldr_reg_address(ThumbAssemblyWriter *self, ARMReg reg, zz_addr_t address);

static void thumb_writer_put_transfer_reg_reg_offset(ThumbAssemblyWriter *self, ThumbMemoryOperation operation,
                                                     ARMReg left_reg, ARMReg right_reg, int32_t right_offset);

void thumb_writer_put_ldr_reg_reg_offset(ThumbAssemblyWriter *self, ARMReg dst_reg, ARMReg src_reg, int32_t src_offset);

void thumb_writer_put_str_reg_reg_offset(ThumbAssemblyWriter *self, ARMReg src_reg, ARMReg dst_reg, int32_t dst_offset);

void thumb_writer_put_str_index_reg_reg_offset(ThumbAssemblyWriter *self, ARMReg src_reg, ARMReg dst_reg,
                                               int32_t dst_offset, bool index);

void thumb_writer_put_ldr_index_reg_reg_offset(ThumbAssemblyWriter *self, ARMReg dst_reg, ARMReg src_reg,
                                               int32_t src_offset, bool index);

void thumb_writer_put_str_reg_reg(ThumbAssemblyWriter *self, ARMReg src_reg, ARMReg dst_reg);

void thumb_writer_put_ldr_reg_reg(ThumbAssemblyWriter *self, ARMReg dst_reg, ARMReg src_reg);

void thumb_writer_put_add_reg_imm(ThumbAssemblyWriter *self, ARMReg dst_reg, int32_t imm);

void thumb_writer_put_sub_reg_imm(ThumbAssemblyWriter *self, ARMReg dst_reg, int32_t imm);

void thumb_writer_put_add_reg_reg_imm(ThumbAssemblyWriter *self, ARMReg dst_reg, ARMReg left_reg, int32_t right_value);

void thumb_writer_put_sub_reg_reg_imm(ThumbAssemblyWriter *self, ARMReg dst_reg, ARMReg left_reg, int32_t right_value);

void thumb_writer_put_push_reg(ThumbAssemblyWriter *self, ARMReg reg);

void thumb_writer_put_pop_reg(ThumbAssemblyWriter *self, ARMReg reg);

void thumb_writer_put_add_reg_reg_reg(ThumbAssemblyWriter *self, ARMReg dst_reg, ARMReg left_reg, ARMReg right_reg);

#endif