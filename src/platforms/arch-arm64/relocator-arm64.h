#ifndef platforms_arch_arm64_relocator_h
#define platforms_arch_arm64_relocator_h

#include "instruction.h"
#include "reader-arm64.h"
#include "register-arm64.h"
#include "writer-arm64.h"

#include "std_kit/std_buffer_array.h"
#include "std_kit/std_kit.h"
#include "std_kit/std_list.h"

typedef struct _io_index_t {
  int input_index;
  int output_index;
} io_index_t;

typedef struct _ARM64Relocator {
  ARM64AssemblyReader *input;
  ARM64AssemblyWriter *output;
  list_t *literal_instCTXs;
  list_t *io_indexs;
} ARM64Relocator;

#define arm64_assembly_relocator_cclass(member) cclass(arm64_relocator, member)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus
ARM64Relocator *arm64_assembly_relocator_cclass(new)(ARM64AssemblyReader *input, ARM64AssemblyWriter *output);

void arm64_assembly_relocator_cclass(reset)(ARM64Relocator *self, ARM64AssemblyReader *input,
                                            ARM64AssemblyWriter *output);

void arm64_assembly_relocator_cclass(try_relocate)(void *address, int bytes_min, int *bytes_max);

void arm64_assembly_relocator_cclass(relocate_to)(ARM64Relocator *self, void *target_address);

void arm64_assembly_relocator_cclass(double_write)(ARM64Relocator *self, void *target_address);

void arm64_assembly_relocator_cclass(register_literal_instCTX)(ARM64Relocator *self, ARM64InstructionCTX *instCTX);

void arm64_assembly_relocator_cclass(relocate_write)(ARM64Relocator *self);

void arm64_assembly_relocator_cclass(relocate_write_all)(ARM64Relocator *self);

void arm64_assembly_relocator_cclass(rewrite_LoadLiteral)(ARM64Relocator *self, ARM64InstructionCTX *instCTX);
void arm64_assembly_relocator_cclass(rewrite_BaseCmpBranch)(ARM64Relocator *self, ARM64InstructionCTX *instCTX);
void arm64_assembly_relocator_cclass(rewrite_BranchCond)(ARM64Relocator *self, ARM64InstructionCTX *instCTX);
void arm64_assembly_relocator_cclass(rewrite_B)(ARM64Relocator *self, ARM64InstructionCTX *instCTX);
void arm64_assembly_relocator_cclass(rewrite_BL)(ARM64Relocator *self, ARM64InstructionCTX *instCTX);
#ifdef __cplusplus
}
#endif //__cplusplus
#endif
