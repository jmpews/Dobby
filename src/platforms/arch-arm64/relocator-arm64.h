#ifndef platforms_arch_arm64_relocator_h
#define platforms_arch_arm64_relocator_h

#include "zkit.h"

#include "memhelper.h"
#include "writer.h"

#include "instructions.h"
#include "reader-arm64.h"
#include "regs-arm64.h"
#include "writer-arm64.h"

typedef struct _ARM64RelocatorInstruction {
    ARM64InstructionCTX *origin_insn;
    ARM64InstructionCTX **relocated_insnCTXs;
    zz_size_t output_index_start;
    zz_size_t ouput_index_end;
    zz_size_t relocated_insnCTXs_count;
} ARM64RelocatorInstruction;

typedef struct _ARM64Relocator {
    bool try_relocated_again;
    zz_size_t try_relocated_length;

    ARM64AssemblyrWriter *output;
    ARM64AssemblyReader *input;

    int needRelocateInputCount;
    int doneRelocateInputCount;

    // memory patch can't confirm the code slice length, so last setp of memory patch need repair the literal instruction.
    ARM64InstructionCTX *literal_insnCTXs[MAX_INSN_SIZE];
    zz_size_t literal_insnCTXs_count;

    // record for every instruction need to be relocated
    ARM64RelocatorInstruction relocator_insnCTXs[MAX_INSN_SIZE];
    zz_size_t relocated_insnCTXs_count;
} ARM64Relocator;

void arm64_relocator_init(ARM64Relocator *relocator, ARM64AssemblyReader *input, ARM64AssemblyrWriter *output);

void arm64_relocator_free(ARM64Relocator *relocator);

void arm64_relocator_reset(ARM64Relocator *self, ARM64AssemblyReader *input, ARM64AssemblyrWriter *output);

void arm64_relocator_relocate_writer(ARM64Relocator *relocator, zz_addr_t final_relocate_address);

void arm64_relocator_write_all(ARM64Relocator *self);

void arm64_relocator_read_one(ARM64Relocator *self, ARM64InstructionCTX *instruction);

void arm64_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes);

bool arm64_relocator_write_one(ARM64Relocator *self);

bool arm64_relocator_double_write(ARM64Relocator *self, zz_addr_t final_address);

#endif