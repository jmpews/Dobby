#ifndef platforms_arch_thumb_writer_thumb_h
#define platforms_arch_thumb_writer_thumb_h

#include <string.h>

#include "hookzz.h"
#include "zkit.h"

#include "macros.h"
#include "memhelper.h"
#include "writer.h"

#include "instructions.h"
#include "reader-thumb.h"
#include "regs-arm.h"
#include "writer-arm.h"
#include "writer-thumb.h"

typedef ARMAssemblerWriter ThumbAssemblerWriter;

typedef enum _ThumbMemoryOperation { ZZ_THUMB_MEMORY_LOAD,
                                     ZZ_THUMB_MEMORY_STORE } ThumbMemoryOperation;

// ------- user custom -------

void thumb_writer_put_ldr_b_reg_address(ThumbAssemblerWriter *self, ARMReg reg, zz_addr_t address);

// ------- architecture default -------

ThumbAssemblerWriter *thumb_writer_new();

void thumb_writer_init(ThumbAssemblerWriter *self, zz_addr_t insns_buffer, zz_addr_t target_ptr);

void thumb_writer_reset(ThumbAssemblerWriter *self, zz_addr_t insns_buffer, zz_addr_t target_ptr);

void thumb_writer_free(ThumbAssemblerWriter *self);

zz_size_t thumb_writer_near_jump_range_size();

void thumb_writer_put_nop(ThumbAssemblerWriter *self);

void thumb_writer_put_bytes(ThumbAssemblerWriter *self, char *data, zz_size_t data_size);

void thumb_writer_put_instruction(ThumbAssemblerWriter *self, uint16_t insn);

void thumb_writer_put_b_imm(ThumbAssemblerWriter *self, uint32_t imm);

void thumb_writer_put_bx_reg(ThumbAssemblerWriter *self, ARMReg reg);

void thumb_writer_put_blx_reg(ThumbAssemblerWriter *self, ARMReg reg);

void thumb_writer_put_branch_imm(ThumbAssemblerWriter *self, uint32_t imm, bool link, bool thumb);

void thumb_writer_put_bl_imm(ThumbAssemblerWriter *self, uint32_t imm);

void thumb_writer_put_blx_imm(ThumbAssemblerWriter *self, uint32_t imm);

void thumb_writer_put_b_imm32(ThumbAssemblerWriter *self, uint32_t imm);

void thumb_writer_put_ldr_reg_imm(ThumbAssemblerWriter *self, ARMReg reg, int32_t imm);

void thumb_writer_put_ldr_reg_address(ThumbAssemblerWriter *self, ARMReg reg, zz_addr_t address);

static void thumb_writer_put_transfer_reg_reg_offset(ThumbAssemblerWriter *self, ThumbMemoryOperation operation,
                                                     ARMReg left_reg, ARMReg right_reg, int32_t right_offset);

void thumb_writer_put_ldr_reg_reg_offset(ThumbAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg,
                                         int32_t src_offset);

void thumb_writer_put_str_reg_reg_offset(ThumbAssemblerWriter *self, ARMReg src_reg, ARMReg dst_reg,
                                         int32_t dst_offset);

void thumb_writer_put_str_index_reg_reg_offset(ThumbAssemblerWriter *self, ARMReg src_reg, ARMReg dst_reg,
                                               int32_t dst_offset, bool index);

void thumb_writer_put_ldr_index_reg_reg_offset(ThumbAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg,
                                               int32_t src_offset, bool index);

void thumb_writer_put_str_reg_reg(ThumbAssemblerWriter *self, ARMReg src_reg, ARMReg dst_reg);

void thumb_writer_put_ldr_reg_reg(ThumbAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg);

void thumb_writer_put_add_reg_imm(ThumbAssemblerWriter *self, ARMReg dst_reg, int32_t imm);

void thumb_writer_put_sub_reg_imm(ThumbAssemblerWriter *self, ARMReg dst_reg, int32_t imm);

void thumb_writer_put_add_reg_reg_imm(ThumbAssemblerWriter *self, ARMReg dst_reg, ARMReg left_reg,
                                      int32_t right_value);

void thumb_writer_put_sub_reg_reg_imm(ThumbAssemblerWriter *self, ARMReg dst_reg, ARMReg left_reg,
                                      int32_t right_value);

void thumb_writer_put_push_reg(ThumbAssemblerWriter *self, ARMReg reg);

void thumb_writer_put_pop_reg(ThumbAssemblerWriter *self, ARMReg reg);

void thumb_writer_put_add_reg_reg_reg(ThumbAssemblerWriter *self, ARMReg dst_reg, ARMReg left_reg,
                                      ARMReg right_reg);

#endif