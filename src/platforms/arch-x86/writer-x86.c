#include "writer-x86.h"
#include <stdlib.h>
#include <string.h>

X86AssemblerWriter *x86_writer_new(zz_ptr_t insns_buffer) {
}

void x86_writer_init(X86AssemblerWriter *self, zz_addr_t insns_buffer, zz_addr_t target_ptr) {
}

void x86_writer_reset(X86AssemblerWriter *self, zz_addr_t insns_buffer, zz_addr_t target_ptr) {
}

void x86_writer_free(X86AssemblerWriter *self) {
}

zz_size_t x86_writer_near_jump_range_size() {
  return 0;
}

void x86_writer_put_ldr_br_b_reg_address(X86AssemblerWriter *self, X86Reg reg, zz_addr_t address) {
}

// ======= default =======

void x86_writer_put_bytes(X86AssemblerWriter *self, char *data, zz_size_t data_size) {
}

void x86_writer_put_instruction(X86AssemblerWriter *self, char *insn) {
}
