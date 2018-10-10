#include "reader-arm.h"
#include "core.h"

inline void ReadBytes(void *data, void *address, int length);

void ReadBytes(void *data, void *address, int length) {
  memcpy(data, address, length);
}

ARMAssemblyReader *arm_assembly_reader_cclass(new)(void *buffer, void *pc) {
  assert((pc % 4) == 0);
  ARMAssemblyReader *reader = SAFE_MALLOC_TYPE(ARMAssemblyReader);
  reader->buffer            = buffer;
  reader->pc                = pc;
  reader->instCTXs          = list_new();
  reader->inst_bytes        = buffer_array_create(64);
  return reader;
}

void arm_assembly_reader_cclass(reset)(ARMAssemblyReader *self, void *buffer, void *pc) {
  self->buffer = buffer;
  self->pc     = pc;

  list_destroy(self->instCTXs);
  self->instCTXs = list_new();

  buffer_array_clear(self->inst_bytes);
  return;
}

ARMInstructionCTX *arm_assembly_reader_cclass(read_inst)(ARMAssemblyReader *self) {
  ARMInstructionCTX *instCTX = SAFE_MALLOC_TYPE(ARMInstructionCTX);

  instCTX->pc      = (zz_addr_t)self->pc + self->inst_bytes->size;
  instCTX->address = (zz_addr_t)self->buffer + self->inst_bytes->size;
  instCTX->size    = 4;

  ReadBytes((void *)&instCTX->bytes, (void *)instCTX->address, 4);

  buffer_array_put(self->inst_bytes, (void *)instCTX->address, 4);

  list_rpush(self->instCTXs, list_node_new(instCTX));
  return instCTX;
}