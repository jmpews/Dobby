#ifndef platforms_arch_arm64_relocator_h
#define platforms_arch_arm64_relocator_h

#include "kitzz.h"

#include "memory.h"
#include "writer.h"

#include "instructions.h"
#include "reader-arm64.h"
#include "regs-arm64.h"
#include "writer-arm64.h"

typedef struct _ZzARM64Relocator {
    bool try_relocated_again;
    zz_size_t try_relocated_length;
    ZzARM64AssemblerWriter *output;
    ZzARM64Reader *input;
    int inpos;
    int outpos;
    // memory patch can't confirm the code slice length, so last setp of memory patch need repair the literal instruction.
    ZzARM64Instruction *literal_insns[MAX_INSN_SIZE];
    zz_size_t literal_insn_size;
} ZzARM64Relocator;

void zz_arm64_relocator_init(ZzARM64Relocator *relocator, ZzARM64Reader *input, ZzARM64AssemblerWriter *output);

void zz_arm64_relocator_free(ZzARM64Relocator *relocator);

void zz_arm64_relocator_reset(ZzARM64Relocator *self, ZzARM64Reader *input, ZzARM64AssemblerWriter *output);

void zz_arm64_relocator_write_all(ZzARM64Relocator *self);

zz_size_t zz_arm64_relocator_read_one(ZzARM64Relocator *self, ZzARM64Instruction *instruction);

void zz_arm64_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes);

bool zz_arm64_relocator_write_one(ZzARM64Relocator *self);

#endif