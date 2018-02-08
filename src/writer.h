#ifndef writer_h
#define writer_h

#include "hookzz.h"
#include "kitzz.h"

#define MAX_LITERAL_INSN_SIZE 128

// literal instruction
typedef struct _ZzLiteralInstruction {
    zz_ptr_t literal_insn_ptr;
    zz_addr_t *literal_address_ptr;
} ZzLiteralInstruction;

typedef struct _ZzAssemblerWriter {
    zz_ptr_t codedata; // writer temporary buffer
    zz_ptr_t base;     // dest
    zz_addr_t pc;      // current pc register
    zz_size_t size;

    ZzLiteralInstruction literal_insns[MAX_LITERAL_INSN_SIZE]; // literal instruction set
    zz_size_t literal_insn_size;
} ZzAssemblerWriter;

#endif
