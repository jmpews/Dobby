#include "writer-thumb.h"

#include <assert.h>
#include <stdlib.h>

inline void ReadBytes(void *data, void *address, int length) {
  memcpy(data, address, length);
}

ThumbAssemblyWriter *thumb_assembly_writer_cclass(new)(void *pc) {
  ThumbAssemblyWriter *writer = SAFE_MALLOC_TYPE(ThumbAssemblyWriter);
  writer->start_pc            = pc;
  writer->instCTXs            = list_new();
  writer->inst_bytes          = buffer_array_create(64);
  writer->ldr_address_stubs   = list_new();
  return writer;
}

void thumb_assembly_writer_cclass(destory)(ThumbAssemblyWriter *self) {
  list_destroy(self->instCTXs);
}

void thumb_assembly_writer_cclass(reset)(ThumbAssemblyWriter *self, void *pc) {
  self->start_pc = pc;

  list_destroy(self->instCTXs);
  self->instCTXs = list_new();

  list_destroy(self->ldr_address_stubs);
  self->ldr_address_stubs = list_new();

  buffer_array_clear(self->inst_bytes);

  return;
}

size_t thumb_assembly_writer_cclass(t2_bxxx_range)() {
  return ((1 << 23) << 2);
}

void thumb_assembly_writer_cclass(patch_to)(ThumbAssemblyWriter *self, void *target_address) {
  self->start_address = target_address;
  memory_manager_t *memory_manager;
  memory_manager = memory_manager_cclass(shared_instance)();
  memory_manager_cclass(patch_code)(memory_manager, target_address, self->inst_bytes->data, self->inst_bytes->size);
  return;
}

#define Thumb_INST_SIZE 2

void thumb_assembly_writer_cclass(put_bytes)(ThumbAssemblyWriter *self, void *data, int length) {
  for (int i = 0; i < (length / Thumb_INST_SIZE); i++) {
    ThumbInstructionCTX *instCTX = SAFE_MALLOC_TYPE(ThumbInstructionCTX);
    instCTX->pc                  = (zz_addr_t)self->start_pc + self->instCTXs.len * Thumb_INST_SIZE;
    instCTX->size                = Thumb_INST_SIZE;

    ReadBytes(&instCTX->bytes, (void *)((zz_addr_t)data + Thumb_INST_SIZE * i), Thumb_INST_SIZE);
    buffer_array_put(self->inst_bytes, (void *)((zz_addr_t)data + Thumb_INST_SIZE * i), Thumb_INST_SIZE);

    list_rpush(self->instCTXs, list_node_new(instCTX));
  }
}

void thumb_assembly_writer_cclass(put_t1_nop)(ThumbAssemblyWriter *self) {
  uint16_t t1_nop_inst = 0x46c0;
  thumb_assembly_writer_cclass(put_bytes)(self, &t1_nop_inst, 2);
  return;
}

// LDR (literal)
// ldr.w reg, [pc, #imm]
void thumb_assembly_writer_cclass(put_t2_ldr_literal_imm)(ThumbAssemblyWriter *self, ARMReg reg, int32_t imm) {
  ARMRegInfo ri;
  arm_register_describe(reg, &ri);

  uint32_t U = 0, Rt_ndx;
  Rt_ndx     = ri.index;

  if (imm >= 0)
    U = 1;

  uint16_t t1_inst;
  t1_inst = 0xf85f | (U << 7);
  thumb_assembly_writer_cclass(put_bytes)(self, &t1_inst, 2);
  t1_inst = (Rt_ndx << 12) | ABS(imm);
  thumb_assembly_writer_cclass(put_bytes)(self, &t1_inst, 2);
  return;
}

// B
// b.w with encodingT4
void thumb_assembly_writer_cclass(put_t2_b_imm)(ThumbAssemblyWriter *self, uint32_t imm) {

  uint32_t S = 0, J1 = 1, J2 = 1;
  uint32_t imm10 = 0, imm11 = 0;

  imm11 = get_insn_sub(imm, 1, 11);
  imm10 = get_insn_sub(imm, 12, 10);

  uint16_t t1_inst;
  t1_inst = 0xf000 | S << 10 | imm10;
  thumb_assembly_writer_cclass(put_bytes)(self, &t1_inst, 2);

  t1_inst = 0x9000 | J1 << 13 | J2 << 11 | imm11;
  thumb_assembly_writer_cclass(put_bytes)(self, &t1_inst, 2);

  return;
}

// combine instructions set.
// 0x4: ldr.w reg, [pc, #0]
// 0x8: b.w 0x0
// 0xc: .long 0x1234
void thumb_assembly_writer_cclass(load_reg_address_and_b)(ThumbAssemblyWriter *self, ARMReg reg, uint32_t address) {
  ARMRegInfo ri;
  arm_register_describe(reg, &ri);

  thumb_assembly_writer_cclass(put_t2_ldr_literal_imm)(self, reg, 0x0);
  thumb_assembly_writer_cclass(put_t2_b_imm)(self, 0x0);
  thumb_assembly_writer_cclass(put_bytes)(self, (zz_ptr_t)&address, sizeof(zz_ptr_t));
  return;
}

static void thumb_assembly_writer_register_ldr_address_stub(ThumbAssemblyWriter *writer, int ldr_inst_index,
                                                            zz_addr_t address) {
  ldr_address_stub_t *ldr_stub = SAFE_MALLOC_TYPE(ldr_address_stub_t);
  ldr_stub->address            = address;
  ldr_stub->ldr_inst_index     = ldr_inst_index;
  list_lpush(writer->ldr_address_stubs, list_node_new(ldr_stub));
  return;
}

// combine instructions set
// 0x4: ldr.w reg, [pc, #label]
void thumb_assembly_writer_cclass(load_reg_address)(ThumbAssemblyWriter *self, ARMReg reg, zz_addr_t address) {
  thumb_assembly_writer_register_ldr_address_stub(self, self->instCTXs->len, address);
  thumb_assembly_writer_cclass(put_t2_ldr_literal_imm)(self, reg, -1);
  return;
}