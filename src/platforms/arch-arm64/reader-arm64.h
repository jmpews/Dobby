#ifndef platforms_arch_arm64_reader_h
#define platforms_arch_arm64_reader_h

#include "zkit.h"

#include "instructions.h"

#include "ARM64AssemblyCore.h"

#include "platforms/backend-linux/memory-linux.h"

typedef enum _ARM64InsnType {
    ARM64_INS_LDR_literal,
    ARM64_INS_ADR,
    ARM64_INS_ADRP,
    ARM64_INS_B,
    ARM64_INS_BL,
    ARM64_INS_B_cond,
    ARM64_UNDEF
} ARM64InsnType;

#define MAX_INSN_SIZE 256
typedef struct _ARM64Reader {
    ARM64InstructionCTX *insnCTXs[MAX_INSN_SIZE];
    zz_size_t insnCTXs_count;
    zz_addr_t start_pc;
    zz_addr_t insns_buffer;
    zz_size_t insns_size;
} ARM64AssemblyReader;

ARM64AssemblyReader *arm64_reader_new(zz_ptr_t insn_address);

void arm64_reader_init(ARM64AssemblyReader *self, zz_ptr_t insn_address);

void arm64_reader_reset(ARM64AssemblyReader *self, zz_ptr_t insn_address);

void arm64_reader_free(ARM64AssemblyReader *self);

ARM64InstructionCTX *arm64_reader_read_one_instruction(ARM64AssemblyReader *self);

#endif