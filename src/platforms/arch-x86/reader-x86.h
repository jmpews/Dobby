#ifndef platforms_arch_x86_reader_h
#define platforms_arch_x86_reader_h

#include "zkit.h"

#include "instructions.h"

#include "platforms/backend-linux/memory-linux.h"

typedef enum _X86InsnType {
    ARM64_UNDEF
} X86InsnType;

X86InsnType GetX86InsnType(uint32_t insn);

#define MAX_INSN_SIZE 256
typedef struct _X86Reader {
    X86Instruction *insnCTXs[MAX_INSN_SIZE];
    zz_size_t insnCTXs_count;
    zz_addr_t start_pc;
    zz_addr_t insns_buffer;
    zz_size_t insns_size;
} X86Reader;

X86Reader *x86_reader_new(zz_ptr_t insn_address);
void x86_reader_init(X86Reader *self, zz_ptr_t insn_address);
void x86_reader_reset(X86Reader *self, zz_ptr_t insn_address);
void x86_reader_free(X86Reader *self);
X86Instruction *x86_reader_read_one_instruction(X86Reader *self);
#endif