#ifndef platforms_arch_arm64_reader_h
#define platforms_arch_arm64_reader_h

#include "zkit.h"

#include "instructions.h"

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

ARM64InsnType GetARM64InsnType(uint32_t insn);

#define MAX_INSN_SIZE 256
typedef struct _ZzARM64Reader {
    ZzARM64Instruction *insns[MAX_INSN_SIZE];
    zz_size_t insn_size;
    zz_addr_t r_start_address;
    zz_addr_t r_current_address;
    zz_addr_t start_pc;
    zz_addr_t current_pc;
    zz_size_t size;
} ZzARM64Reader;

ZzARM64Reader *arm64_reader_new(zz_ptr_t insn_address);
void arm64_reader_init(ZzARM64Reader *self, zz_ptr_t insn_address);
void arm64_reader_reset(ZzARM64Reader *self, zz_ptr_t insn_address);
void arm64_reader_free(ZzARM64Reader *self);
ZzARM64Instruction *arm64_reader_read_one_instruction(ZzARM64Reader *self);
#endif