#include "relocator-x86.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RELOCATOR_INSTRUCIONS_SIZE 64

void x86_relocator_init(X86Relocator *relocator, X86Reader *input, X86AssemblerWriter *output) {
   
}

void x86_relocator_free(X86Relocator *relocator) {

}

void x86_relocator_reset(X86Relocator *self, X86Reader *input, X86AssemblerWriter *output) {
  
}

void x86_relocator_read_one(X86Relocator *self, X86Instruction *instruction) {
    
}

void x86_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes) {
  
}

static X86RelocatorInstruction *x86_relocator_get_relocator_insn_with_address(X86Relocator *self,
                                                                                  zz_addr_t insn_address) {
   
}

void x86_relocator_relocate_writer(X86Relocator *relocator, zz_addr_t final_relocate_address) {
   
}

void x86_relocator_write_all(X86Relocator *self) {
   
}


bool x86_relocator_write_one(X86Relocator *self) {
   
}