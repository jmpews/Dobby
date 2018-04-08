#ifndef platforms_arch_arm_relocator_thumb_h
#define platforms_arch_arm_relocator_thumb_h

#include "hookzz.h"
#include "zkit.h"

#include "memhelper.h"
#include "writer.h"

#include "instructions.h"
#include "reader-thumb.h"
#include "regs-arm.h"
#include "relocator-arm.h"
#include "writer-thumb.h"

typedef struct _ZzThumbRelocator {
    bool try_relocated_again;
    zz_size_t try_relocated_length;
    ZzThumbAssemblerWriter *output;
    ARMReader *input;
    int inpos;
    int outpos;
    // memory patch can't confirm the code slice length, so last setp of memory patch need repair the literal instruction.
    ARMInstruction *literal_insns[MAX_INSN_SIZE];
    zz_size_t literal_insn_size;

    // record for every instruction need to be relocated
    ARMRelocatorInstruction relocator_insns[MAX_INSN_SIZE];
    zz_size_t relocator_insn_size;
} ZzThumbRelocator;

void zz_thumb_relocator_init(ZzThumbRelocator *relocator, ARMReader *input, ZzThumbAssemblerWriter *writer);

void zz_thumb_relocator_reset(ZzThumbRelocator *self, ARMReader *input, ZzThumbAssemblerWriter *output);

void zz_thumb_relocator_read_one(ZzThumbRelocator *self, ARMInstruction *instruction);

bool zz_thumb_relocator_write_one(ZzThumbRelocator *self);

void zz_thumb_relocator_relocate_writer(ZzThumbRelocator *relocator, zz_addr_t final_relocate_address);

void zz_thumb_relocator_write_all(ZzThumbRelocator *self);

void zz_thumb_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes);

#endif