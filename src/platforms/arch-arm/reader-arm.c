#include "reader-arm.h"
#include <stdlib.h>

ARMReader *arm_reader_new(zz_ptr_t insn_address) {
  ARMReader *reader = (ARMReader *)malloc0(sizeof(ARMReader));

  reader->start_pc       = (zz_addr_t)insn_address + 8;
  reader->insns_buffer   = (zz_addr_t)insn_address;
  reader->insns_size     = 0;
  reader->insnCTXs_count = 0;
  return reader;
}

void arm_reader_init(ARMReader *self, zz_ptr_t insn_address) {
  arm_reader_reset(self, insn_address);
}

void arm_reader_reset(ARMReader *self, zz_ptr_t insn_address) {
  self->start_pc       = (zz_addr_t)insn_address + 8;
  self->insns_buffer   = (zz_addr_t)insn_address;
  self->insns_size     = 0;
  self->insnCTXs_count = 0;
}

void arm_reader_free(ARMReader *self) {
  if (self->insnCTXs_count) {
    for (int i = 0; i < self->insnCTXs_count; i++) {
      free(self->insnCTXs[i]);
    }
  }
  free(self);
}

ARMInstruction *arm_reader_read_one_instruction(ARMReader *self) {
  ARMInstruction *insn_ctx    = (ARMInstruction *)malloc0(sizeof(ARMInstruction));
  zz_addr_t next_insn_address = (zz_addr_t)self->insns_buffer + self->insns_size;
  zz_addr_t next_pc           = (zz_addr_t)self->start_pc + self->insns_size;

  insn_ctx->type    = ARM_INSN;
  insn_ctx->pc      = next_pc;
  insn_ctx->address = next_insn_address;
  insn_ctx->insn    = *(uint32_t *)next_insn_address;

  self->insnCTXs[self->insnCTXs_count++] = insn_ctx;
  self->insns_size += insn_ctx->size;
  return insn_ctx;
}

