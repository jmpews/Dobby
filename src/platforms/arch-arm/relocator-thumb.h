#ifndef platforms_arch_relocator_thumb_h
#define platforms_arch_relocator_thumb_h

#include "hookzz.h"
#include "zkit.h"

#include "memhelper.h"
#include "writer.h"

#include "instructions.h"
#include "reader-thumb.h"
#include "regs-arm.h"
#include "relocator-arm.h"
#include "writer-thumb.h"

typedef struct _ThumbRelocator {
  bool try_relocated_again;
  zz_size_t try_relocated_length;
  ThumbAssemblyWriter *output;
  ARMReader *input;
  int needRelocateInputCount;
  int doneRelocateInputCount;
  // memory patch can't confirm the code slice length, so last setp of memory patch need repair the literal instruction.
  ARMInstruction *literal_instCTXs[MAX_INSN_SIZE];
  zz_size_t literal_insnCTXs_count;

  // record for every instruction need to be relocated
  ARMRelocatorInstruction relocator_insnCTXs[MAX_INSN_SIZE];
  zz_size_t relocated_insnCTXs_count;
} ThumbRelocator;

void thumb_relocator_init(ThumbRelocator *relocator, ARMReader *input, ThumbAssemblyWriter *writer);

void thumb_relocator_reset(ThumbRelocator *self, ARMReader *input, ThumbAssemblyWriter *output);

void thumb_relocator_read_one(ThumbRelocator *self, ARMInstruction *instruction);

bool thumb_relocator_write_one(ThumbRelocator *self);

void thumb_relocator_relocate_writer(ThumbRelocator *relocator, zz_addr_t final_relocate_address);

void thumb_relocator_write_all(ThumbRelocator *self);

void thumb_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes);

bool thumb_relocator_double_write(ThumbRelocator *self, zz_addr_t final_address);

#endif