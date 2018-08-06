#ifndef platforms_arch_arm_writer_arm_h
#define platforms_arch_arm_writer_arm_h

#include "instruction.h"
#include "register-arm.h"

#include "std_kit/std_buffer_array.h"
#include "std_kit/std_kit.h"
#include "std_kit/std_list.h"

typedef struct _address_stub_t {
  int ldr_inst_index uintptr_t address;
} ldr_address_stub_t;

typedef struct _ARMAssemblerWriter {
  void *start_pc;
  void *start_address;

  list_t *instCTXs;
  buffer_array_t *inst_bytes;
  list_t *ldr_address_stubs;
} ARMAssemblerWriter;

#define arm_assembly_writer_cclass(member) cclass(arm_assembly_writer, member)
#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

ARMAssemblyWriter *arm_assembly_writer_cclass(new)(void *pc);

#ifdef __cplusplus
}
#endif //__cplusplus
== == == == == == == == == == == == == == == == == == == == == == == == ;
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

void arm_writer_put_ldr_reg_reg_imm_index(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, int32_t imm,
                                          bool index);

void arm_writer_put_ldr_reg_reg_imm_A1(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, uint32_t imm, bool P,
                                       bool U, bool W);

void arm_writer_put_ldr_reg_address(ARMAssemblerWriter *self, ARMReg reg, zz_addr_t address);

void arm_writer_put_add_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, uint32_t imm);

void arm_writer_put_sub_reg_reg_imm(ARMAssemblerWriter *self, ARMReg dst_reg, ARMReg src_reg, uint32_t imm);

void arm_writer_put_push_reg(ARMAssemblerWriter *self, ARMReg reg);

void arm_writer_put_pop_reg(ARMAssemblerWriter *self, ARMReg reg);

#endif