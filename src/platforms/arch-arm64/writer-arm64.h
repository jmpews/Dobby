#ifndef platforms_arch_arm64_writer_arm64_h
#define platforms_arch_arm64_writer_arm64_h

#include "instruction.h"
#include "register-arm64.h"

#include "std_kit/std_buffer_array.h"
#include "std_kit/std_kit.h"
#include "std_kit/std_list.h"

typedef struct _address_stub_t {
  int ldr_inst_index;
  uintptr_t address;
} ldr_address_stub_t;

typedef struct _ARM64AssemblyWriter {
  void *pc;
  void *buffer;

  list_t *instCTXs;
  buffer_array_t *inst_bytes;
  list_t *ldr_address_stubs;
} ARM64AssemblyWriter;

#define arm64_assembly_writer_cclass(member) cclass(arm64_assembly_writer, member)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

ARM64AssemblyWriter *arm64_assembly_writer_cclass(new)(void *pc);

void arm64_assembly_writer_cclass(destory)(ARM64AssemblyWriter *self);

void arm64_assembly_writer_cclass(reset)(ARM64AssemblyWriter *self, void *pc);

// patch code
void arm64_assembly_writer_cclass(patch_to)(ARM64AssemblyWriter *self, void *target_address);

// b xxx range for near jump
size_t arm64_assembly_writer_cclass(bxxx_range)();

void arm64_assembly_writer_cclass(put_bytes)(ARM64AssemblyWriter *self, void *data, int length);

void arm64_assembly_writer_cclass(put_ldr_reg_imm)(ARM64AssemblyWriter *self, ARM64Reg reg, uint32_t offset);
void arm64_assembly_writer_cclass(put_str_reg_reg_offset)(ARM64AssemblyWriter *self, ARM64Reg src_reg,
                                                          ARM64Reg dest_reg, uint64_t offset);
void arm64_assembly_writer_cclass(put_ldr_reg_reg_offset)(ARM64AssemblyWriter *self, ARM64Reg dest_reg,
                                                          ARM64Reg src_reg, uint64_t offset);
void arm64_assembly_writer_cclass(put_br_reg)(ARM64AssemblyWriter *self, ARM64Reg reg);
void arm64_assembly_writer_cclass(put_blr_reg)(ARM64AssemblyWriter *self, ARM64Reg reg);
void arm64_assembly_writer_cclass(put_b_imm)(ARM64AssemblyWriter *self, uint64_t offset);

#ifdef __cplusplus
}
#endif //__cplusplus
#endif