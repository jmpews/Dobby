#ifndef platforms_arch_arm_relocator_arm_h
#define platforms_arch_arm_relocator_arm_h

#include "hookzz.h"
#include "kitzz.h"

#include "memory.h"
#include "writer.h"

#include "instructions.h"
#include "reader-arm.h"
#include "regs-arm.h"
#include "writer-arm.h"

typedef struct _ZzARMRelocator {
    bool try_relocated_again;
    zz_size_t try_relocated_length;
    ZzARMAssemblerWriter *output;
    ZzARMReader *input;
    int inpos;
    int outpos;
    // memory patch can't confirm the code slice length, so last setp of memory patch need repair the literal instruction.
    ZzARMInstruction *literal_insns[MAX_INSN_SIZE];
    zz_size_t literal_insn_size;
} ZzARMRelocator;

void zz_arm_relocator_init(ZzARMRelocator *relocator, ZzARMReader *input, ZzARMAssemblerWriter *output);

void zz_arm_relocator_free(ZzARMRelocator *relocator);

void zz_arm_relocator_reset(ZzARMRelocator *self, ZzARMReader *input, ZzARMAssemblerWriter *output);

void zz_arm_relocator_relocate_writer(ZzARMRelocator *relocator, zz_addr_t final_relocate_address);

void zz_arm_relocator_write_all(ZzARMRelocator *self);

zz_size_t zz_arm_relocator_read_one(ZzARMRelocator *self, ZzARMInstruction *instruction);

void zz_arm_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes);

bool zz_arm_relocator_write_one(ZzARMRelocator *self);

#endif