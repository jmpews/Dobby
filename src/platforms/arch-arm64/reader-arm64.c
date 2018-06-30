#include "reader-arm64.h"
#include "std_kit/std_kit.h"
#include <string.h>

inline void ReadBytes(void *data, void *address, int length);

void ReadBytes(void *data, void *address, int length) { memcpy(data, address, length); }

ARM64AssemblyReader *arm64_assembly_reader_cclass(new)(void *address, void *pc) {
    ARM64AssemblyReader *reader = SAFE_MALLOC_TYPE(ARM64AssemblyReader);
    reader->start_address       = address;
    reader->start_pc            = pc;
    reader->instCTXs            = list_new();
    reader->inst_bytes          = buffer_array_create(64);
    return reader;
}

void arm64_assembly_reader_cclass(reset)(ARM64AssemblyReader *self, void *address, void *pc) {
    self->start_address = address;
    self->start_pc      = pc;

    list_destroy(self->instCTXs);
    self->instCTXs = list_new();

    buffer_array_clear(self->inst_bytes);
    return;
}

ARM64InstructionCTX *arm64_assembly_reader_cclass(read_inst)(ARM64AssemblyReader *self) {
    ARM64InstructionCTX *instCTX = SAFE_MALLOC_TYPE(ARM64InstructionCTX);

    instCTX->pc      = (zz_addr_t)self->start_pc + self->inst_bytes->size;
    instCTX->address = (zz_addr_t)self->start_address + self->inst_bytes->size;
    instCTX->size    = 4;

    ReadBytes((void *)&instCTX->bytes, (void *)instCTX->address, 4);

    buffer_array_put(self->inst_bytes, (void *)instCTX->address, 4);

    list_rpush(self->instCTXs, list_node_new(instCTX));
    return instCTX;
}