#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "memory_manager.h"
#include "writer-arm64.h"

inline void ReadBytes(void *data, void *address, int length) { memcpy(data, address, length); }

ARM64AssemblyWriter *arm64_assembly_writer_cclass(new)(void *pc) {
    ARM64AssemblyWriter *writer = SAFE_MALLOC_TYPE(ARM64AssemblyWriter);
    writer->start_pc            = pc;
    writer->instCTXs            = list_new();
    writer->inst_bytes          = buffer_array_create(64);
    return writer;
}

void arm64_assembly_writer_cclass(destory)(ARM64AssemblyWriter *self) {}

void arm64_assembly_writer_cclass(reset)(ARM64AssemblyWriter *self, void *pc) {
    self->start_pc = pc;

    list_destroy(self->instCTXs);
    self->instCTXs = list_new();

    buffer_array_clear(self->inst_bytes);
    return;
}

void arm64_assembly_writer_cclass(patch_to)(ARM64AssemblyWriter *self, void *target_address) {
    self->start_address = target_address;
    memory_manager_t *memory_manager;
    memory_manager = memory_manager_cclass(shared_instance)();
    memory_manager_cclass(patch_code)(memory_manager, target_address, self->inst_bytes->data, self->inst_bytes->size);
    return;
}

// void arm64_assembly_writer_cclass(near_patch_to)(ARM64AssemblyWriter *self, void *target_address, int range) {
//     self->start_address = target_address;
//     CodeCave *cc;
//     memory_manager_t *memory_manager;
//     memory_manager = memory_manager_cclass(shared_instance)();
//     cc = memory_manager_cclass(search_near_code_cave)(memory_manager, target_address, range, self->inst_bytes->size);
//     XCHECK(cc);
//     memory_manager_cclass(patch_code)(memory_manager, target_address, self->inst_bytes->data, self->inst_bytes->size);
//     SAFE_FREE(cc);
//     return;
// }

// void arm64_assembly_writer_cclass(relocate_patch_to)(ARM64AssemblyWriter *self, void *target_address,
//                                                      ARM64Relocator *relocator) {
//     self->start_address = target_address;
//     CodeSlice *cs;
//     memory_manager_t *memory_manager;
//     memory_manager = memory_manager_cclass(shared_instance)();
//     cs             = memory_manager_cclass(allocate_code_slice)(memory_manager, self->inst_bytes->size);
//     XCHECK(cs);
//     arm64_assembly_relocator_cclass(double_write)(relocator, cs->data);
//     memory_manager_cclass(patch_code)(memory_manager, cs->data, self->inst_bytes->data, self->inst_bytes->size);
//     SAFE_FREE(cc);
//     return;
// }

#define ARM64_INST_SIZE 4

void arm64_assembly_writer_cclass(put_bytes)(ARM64AssemblyWriter *self, void *data, int length) {
    assert(length % 4 == 0);
    for (int i = 0; i < (length / ARM64_INST_SIZE); i++) {
        ARM64InstructionCTX *instCTX = SAFE_MALLOC_TYPE(ARM64InstructionCTX);
        instCTX->pc                  = (zz_addr_t)self->start_pc + self->inst_bytes->size;
        instCTX->address             = (zz_addr_t)self->inst_bytes->data + self->inst_bytes->size;
        instCTX->size                = ARM64_INST_SIZE;

        ReadBytes(&instCTX->bytes, (void *)((zz_addr_t)data + ARM64_INST_SIZE * i), ARM64_INST_SIZE);
        buffer_array_put(self->inst_bytes, (void *)((zz_addr_t)data + ARM64_INST_SIZE * i), ARM64_INST_SIZE);

        list_rpush(self->instCTXs, list_node_new(instCTX));
    }
}

void arm64_assembly_writer_cclass(put_ldr_reg_imm)(ARM64AssemblyWriter *self, ARM64Reg reg, uint32_t offset) {
    ARM64RegInfo ri;
    arm64_register_describe(reg, &ri);

    uint32_t imm19, Rt;
    imm19         = offset >> 2;
    Rt            = ri.index;
    uint32_t inst = 0x58000000 | imm19 << 5 | Rt;

    arm64_assembly_writer_cclass(put_bytes)(self, (void *)&inst, 4);
}
void arm64_assembly_writer_cclass(put_str_reg_reg_offset)(ARM64AssemblyWriter *self, ARM64Reg src_reg,
                                                          ARM64Reg dest_reg, uint64_t offset) {
    ARM64RegInfo rs, rd;
    arm64_register_describe(src_reg, &rs);
    arm64_register_describe(dest_reg, &rd);

    uint32_t size, v = 0, opc = 0, Rn_ndx, Rt_ndx;
    Rn_ndx = rd.index;
    Rt_ndx = rs.index;

    if (rs.is_integer) {
        size = (rs.width == 64) ? 0b11 : 0b10;
    }

    uint32_t imm12 = offset >> size;
    uint32_t inst  = 0x39000000 | size << 30 | opc << 22 | imm12 << 10 | Rn_ndx << 5 | Rt_ndx;
    arm64_assembly_writer_cclass(put_bytes)(self, (void *)&inst, 4);
}
void arm64_assembly_writer_cclass(put_ldr_reg_reg_offset)(ARM64AssemblyWriter *self, ARM64Reg dest_reg,
                                                          ARM64Reg src_reg, uint64_t offset) {
    ARM64RegInfo rs, rd;
    arm64_register_describe(src_reg, &rs);
    arm64_register_describe(dest_reg, &rd);

    uint32_t size, v = 0, opc = 0b01, Rn_ndx, Rt_ndx;
    Rn_ndx = rs.index;
    Rt_ndx = rd.index;

    if (rs.is_integer) {
        size = (rs.width == 64) ? 0b11 : 0b10;
    }

    uint32_t imm12 = offset >> size;
    uint32_t inst  = 0x39000000 | size << 30 | opc << 22 | imm12 << 10 | Rn_ndx << 5 | Rt_ndx;
    arm64_assembly_writer_cclass(put_bytes)(self, (void *)&inst, 4);
}
void arm64_assembly_writer_cclass(put_br_reg)(ARM64AssemblyWriter *self, ARM64Reg reg) {
    ARM64RegInfo ri;
    arm64_register_describe(reg, &ri);

    uint32_t op   = 0, Rn_ndx;
    Rn_ndx        = ri.index;
    uint32_t inst = 0xd61f0000 | op << 21 | Rn_ndx << 5;
    arm64_assembly_writer_cclass(put_bytes)(self, (void *)&inst, 4);
}
void arm64_assembly_writer_cclass(put_blr_reg)(ARM64AssemblyWriter *self, ARM64Reg reg) {
    ARM64RegInfo ri;
    arm64_register_describe(reg, &ri);

    uint32_t op = 0b01, Rn_ndx;

    Rn_ndx        = ri.index;
    uint32_t inst = 0xd63f0000 | op << 21 | Rn_ndx << 5;
    arm64_assembly_writer_cclass(put_bytes)(self, (void *)&inst, 4);
}
void arm64_assembly_writer_cclass(put_b_imm)(ARM64AssemblyWriter *self, uint64_t offset) {
    uint32_t op   = 0b0, imm26;
    imm26         = (offset >> 2) & 0x03ffffff;
    uint32_t inst = 0x14000000 | op << 31 | imm26;
    arm64_assembly_writer_cclass(put_bytes)(self, (void *)&inst, 4);
}