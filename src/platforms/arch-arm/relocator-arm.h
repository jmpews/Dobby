#ifndef platforms_arch_arm_relocator_arm_h
#define platforms_arch_arm_relocator_arm_h

#include "hookzz.h"
#include "zkit.h"

#include "memhelper.h"
#include "writer.h"

#include "instructions.h"
#include "reader-arm.h"
#include "regs-arm.h"
#include "writer-arm.h"

typedef struct _ARMRelocatorInstruction {
    ARMInstruction *origin_insn;
    ARMInstruction **relocated_insnCTXs;
    zz_size_t output_index_start;
    zz_size_t ouput_index_end;
    zz_size_t relocated_insnCTXs_count;
} ARMRelocatorInstruction;

typedef struct _ARMRelocator {
    bool try_relocated_again;
    zz_size_t try_relocated_length;
    ARMAssemblerWriter *output;
    ARMReader *input;
    int needRelocateInputCount;
    int doneRelocateInputCount;

    // memory patch can't confirm the code slice length, so last setp of memory patch need repair the literal instruction.
    ARMInstruction *literal_insnCTXs[MAX_INSN_SIZE];
    zz_size_t literal_insnCTXs_count;

    // record for every instruction need to be relocated
    ARMRelocatorInstruction relocator_insnCTXs[MAX_INSN_SIZE];
    zz_size_t relocated_insnCTXs_count;
} ARMRelocator;

void arm_relocator_init(ARMRelocator *relocator, ARMReader *input, ARMAssemblerWriter *output);

void arm_relocator_free(ARMRelocator *relocator);

void arm_relocator_reset(ARMRelocator *self, ARMReader *input, ARMAssemblerWriter *output);

void arm_relocator_relocate_writer(ARMRelocator *relocator, zz_addr_t final_relocate_address);

void arm_relocator_write_all(ARMRelocator *self);

void arm_relocator_read_one(ARMRelocator *self, ARMInstruction *instruction);

void arm_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes);

bool arm_relocator_write_one(ARMRelocator *self);

#endif