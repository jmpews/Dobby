#ifndef platforms_arch_x86_relocator_h
#define platforms_arch_x86_relocator_h

#include "zkit.h"

#include "memhelper.h"
#include "writer.h"

#include "instructions.h"
#include "reader-x86.h"
#include "regs-x86.h"
#include "writer-x86.h"

typedef struct _X86RelocatorInstruction {
    X86Instruction *origin_insn;
    X86Instruction **relocated_insnCTXs;
    zz_size_t output_index_start;
    zz_size_t ouput_index_end;
    zz_size_t relocated_insn_size;
    zz_size_t size;
} X86RelocatorInstruction;

typedef struct _X86Relocator {
    bool try_relocated_again;
    zz_size_t try_relocated_length;
    X86AssemblerWriter *output;
    X86Reader *input;
    int needRelocateInputCount;
    int doneRelocateInputCount;

    // memory patch can't confirm the code slice length, so last setp of memory patch need repair the literal instruction.
    X86Instruction *literal_insnCTXs[MAX_INSN_SIZE];
    zz_size_t literal_insnCTXs_count;

    // record for every instruction need to be relocated
    X86RelocatorInstruction relocator_insnCTXs[MAX_INSN_SIZE];
    zz_size_t relocated_insnCTXs_count;
} X86Relocator;

void x86_relocator_init(X86Relocator *relocator, X86Reader *input, X86AssemblerWriter *output);

void x86_relocator_free(X86Relocator *relocator);

void x86_relocator_reset(X86Relocator *self, X86Reader *input, X86AssemblerWriter *output);

void x86_relocator_relocate_writer(X86Relocator *relocator, zz_addr_t final_relocate_address);

void x86_relocator_write_all(X86Relocator *self);

void x86_relocator_read_one(X86Relocator *self, X86Instruction *instruction);

void x86_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes);

bool x86_relocator_write_one(X86Relocator *self);

#endif