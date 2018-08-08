#include "ARM64AssemblyCore.h"
#include "relocator-arm64.h"
#include "std_kit/std_kit.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

ARM64Relocator *arm64_assembly_relocator_cclass(new)(ARM64AssemblyReader *input, ARM64AssemblyWriter *output) {
  ARM64Relocator *relocator   = SAFE_MALLOC_TYPE(ARM64Relocator);
  relocator->input            = input;
  relocator->output           = output;
  relocator->io_indexs        = list_new();
  relocator->literal_instCTXs = list_new();
  return relocator;
}

void arm64_assembly_relocator_cclass(reset)(ARM64Relocator *self, ARM64AssemblyReader *input,
                                            ARM64AssemblyWriter *output) {
  arm64_assembly_reader_reset(self->input, 0, 0);
  arm64_assembly_writer_reset(self->output, 0);

  list_destroy(self->literal_instCTXs);
  self->literal_instCTXs = list_new();
  list_destroy(self->io_indexs);
  self->io_indexs = list_new();
}

void arm64_assembly_relocator_cclass(try_relocate)(void *address, int bytes_min, int *bytes_max) {
  int tmp_size   = 0;
  bool early_end = false;

  ARM64InstructionCTX *instCTX = NULL;
  ARM64AssemblyReader *reader  = arm64_assembly_reader_cclass(new)(address, address);

  do {
    instCTX = arm64_assembly_reader_cclass(read_inst)(reader);
    switch (getInstType(instCTX->bytes)) {
    case BImm:
      early_end = true;
      break;
    default:;
    }
    tmp_size += instCTX->size;

  } while (tmp_size < bytes_min);

  if (early_end) {
    *bytes_max = bytes_min;
  }
  // TODO: free ARM64AssemblyReader
  SAFE_FREE(reader);
}

void arm64_assembly_relocator_cclass(relocate_to)(ARM64Relocator *self, void *target_address) {
  list_iterator_t *it = list_iterator_new(self->literal_instCTXs, LIST_HEAD);
  for (int i; i < self->literal_instCTXs->len; i++) {
    ARM64InstructionCTX *instCTX = (ARM64InstructionCTX *)(list_at(self->literal_instCTXs, i)->val);
    zz_addr_t literal_target_address;
    literal_target_address = *(zz_addr_t *)instCTX->address;
    if (literal_target_address > (zz_addr_t)self->input->start_pc &&
        literal_target_address < ((zz_addr_t)self->input->start_pc + self->input->inst_bytes->size)) {
      list_iterator_t *it_a = list_iterator_new(self->io_indexs, LIST_HEAD);
      for (int j; j < self->io_indexs->len; j++) {
        io_index_t *io_index               = (io_index_t *)(list_at(self->io_indexs, j)->val);
        int i_index                        = io_index->input_index;
        int o_index                        = io_index->output_index;
        ARM64InstructionCTX *inputInstCTX  = (ARM64InstructionCTX *)(list_at(self->input->instCTXs, i_index)->val);
        ARM64InstructionCTX *outputInstCTX = (ARM64InstructionCTX *)(list_at(self->output->instCTXs, o_index)->val);
        if (inputInstCTX->address == literal_target_address) {
          *(zz_addr_t *)instCTX->address =
              ((ARM64InstructionCTX *)(list_at(self->output->instCTXs, o_index)->val))->pc -
              (zz_addr_t)self->output->start_pc + (zz_addr_t)target_address;
          break;
        }
      }
    }
  }
}

void arm64_assembly_relocator_cclass(register_literal_instCTX)(ARM64Relocator *self, ARM64InstructionCTX *instCTX) {
  list_rpush(self->literal_instCTXs, list_node_new(instCTX));
}

void arm64_assembly_relocator_cclass(double_write)(ARM64Relocator *self, void *target_address) {
  assert((zz_addr_t)target_address % 4 == 0);

  int origin_inst_buffer_size = self->output->inst_bytes->size;

  // temporary store inst buffer
  void *tmp_inst_buffer = (void *)malloc(self->output->inst_bytes->size);
  memcpy(tmp_inst_buffer, self->output->inst_bytes->data, self->output->inst_bytes->size);

  arm64_assembly_writer_cclass(reset)(self->output, target_address);
  arm64_assembly_relocator_cclass(reset)(self, self->input, self->output);

  arm64_assembly_relocator_cclass(relocate_write_all)(self);

  void *no_need_relocate_inst_buffer = (void *)((zz_addr_t)tmp_inst_buffer + self->output->inst_bytes->size);
  arm64_assembly_writer_cclass(put_bytes)(self->output, no_need_relocate_inst_buffer,
                                          origin_inst_buffer_size - self->output->inst_bytes->size);
}

void arm64_assembly_relocator_cclass(relocate_write_all)(ARM64Relocator *self) {
  do {
    arm64_assembly_relocator_cclass(relocate_write)(self);
  } while (self->io_indexs->len < self->input->instCTXs->len);
}

void arm64_assembly_relocator_cclass(relocate_write)(ARM64Relocator *self) {
  ARM64InstructionCTX *instCTX = NULL;
  bool rewritten               = true;

  int done_relocated_input_count;
  done_relocated_input_count = self->io_indexs->len;

  if (self->input->instCTXs->len > self->io_indexs->len) {
    instCTX = (ARM64InstructionCTX *)(list_at(self->input->instCTXs, done_relocated_input_count)->val);
  } else
    return;

  // push relocate input <-> output index
  io_index_t *io_index   = SAFE_MALLOC_TYPE(io_index_t);
  io_index->input_index  = done_relocated_input_count;
  io_index->output_index = self->output->instCTXs->len;
  list_rpush(self->io_indexs, list_node_new(io_index));

  switch (getInstType(instCTX->bytes)) {
  case LoadLiteral:
    arm64_assembly_relocator_cclass(rewrite_LoadLiteral)(self, instCTX);
    break;
  case BaseCmpBranch:
    arm64_assembly_relocator_cclass(rewrite_BaseCmpBranch)(self, instCTX);
    break;
  case BranchCond:
    arm64_assembly_relocator_cclass(rewrite_BranchCond)(self, instCTX);
    break;
  case B:
    arm64_assembly_relocator_cclass(rewrite_B)(self, instCTX);
    break;
  case BL:
    arm64_assembly_relocator_cclass(rewrite_BL)(self, instCTX);
    break;
  default:
    rewritten = false;
    break;
  }
  if (!rewritten) {
    arm64_assembly_writer_cclass(put_bytes)(self->output, (void *)&instCTX->bytes, instCTX->size);
  }
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

void thumb_assembly_relocator_cclass(reWrite_thumb_adr_pcrel_10)(ARMRelocator *self,
                                                                                    ARMInstructionCTX *instCTX) {
  uint32_t addr, target_address;
  uint32_t Rd_ndx;

  Rd_ndx         = get_insn_sub(instCTX->bytes, 8, 3);
  addr           = get_insn_sub(instCTX->bytes, 0, 8);
  target_address = addr + instCTX->pc;

  if (self->output->pc % 4) {
    thumb_assembly_writer_cclass(put_t1_nop);
  }

  ARMReg Rd = arm_register_revert_describe(Rd_ndx, 0);

  // 0x4: ldr.w Rd, [pc, 0x0]
  thumb_assembly_writer_cclass(put_load_reg_address)(self->output, Rd, target_address);

  // thumb_assembly_relocator_cclass(register_literal_instCTX)(self, (ARMInstructionCTX *)(list_at(self->output->instCTXs, self->output->instCTXs->len - 2))->val);
}

void thumb_assembly_relocator_cclass(cclass_3_parent(tBcc, T1I, T1BranchCond, Sched))(ARMRelocator *self,
                                                                                      ARMInstructionCTX *instCTX) {
  uint32_t target, target_address;
  uint32_t p;

  p              = get_insn_sub(instCTX->bytes, 8, 4);
  target         = get_insn_sub(instCTX->bytes, 0, 8);
  target_address = target + instCTX->pc;

  if (self->output->pc % 4) {
    thumb_assembly_writer_cclass(put_nop);
  }

  // 0x4: bcc 0x0
  // 0x6: nop
  // 0x8: b.w 0x0
  // 0xc: ldr.w pc, [pc, #label]
  uint32_t origin_bcc_thumb_inst = get_insn_sub(instCTX->bytes, 0, 16);
  uint32_t fixed_bcc_thumb_inst  = ((origin_bcc_thumb_inst & 0b1111111100000000) | 0);

  // convert origin bcc to offset-fixed bcc, and  make it 4 Bytes
  thumb_assembly_writer_cclass(put_bytes)(self->output, (uint16_t *)&fixed_bcc_thumb_inst, sizeof(uint16_t));
  thumb_assembly_writer_cclass(put_t1_nop)(self->output);

  thumb_assembly_writer_cclass(put_t2_b)(self->output, 0x0);
  thumb_assembly_writer_cclass(load_reg_address)(self->output, ARM_REG_PC, target_address);

  // thumb_assembly_relocator_cclass(register_literal_instCTX)(self, (ARMInstructionCTX *)(list_at(self->output->instCTXs, self->output->instCTXs->len - 2))->val);
}

void thumb_assembly_relocator_cclass(cclass_3_parent(tBL, TIx2, Requires, Sched))(ARMRelocator *self,
                                                                                  ARMInstructionCTX *instCTX) {
  uint32_t func, target_address;
  func = get_insn_sub(instCTX->bytes, 0, 11);
  func = func | (get_insn_sub(instCTX->bytes, 16, 10) << 11);
  func = func | (get_insn_sub(instCTX->bytes, 11, 1) << 21);
  func = func | (get_insn_sub(instCTX->bytes, 13, 1) << 22);
  func = func | (get_insn_sub(instCTX->bytes, 26, 1) << 23);

  target_address = func + instCTX->pc;

  if (self->output->pc % 4) {
    thumb_assembly_writer_cclass(put_nop);
  }

  // 0x4: ldr.w lr, [pc, #label]
  // 0x8: ldr.w pc, [pc, #babel]
  // 0xc: xxx
  thumb_assembly_writer_cclass(put_load_address)(self->output, ARM_REG_LR, instCTX->pc + 4);
  thumb_assembly_writer_cclass(put_load_address)(self->output, ARM_REG_pC, target_address);

  // thumb_assembly_relocator_cclass(register_literal_instCTX)(self, (ARMInstructionCTX *)(list_at(self->output->instCTXs, self->output->instCTXs->len - 2))->val);
}