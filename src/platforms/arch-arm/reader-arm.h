#ifndef platforms_arch_arm_reader_arm_h
#define platforms_arch_arm_reader_arm_h

#include "hookzz.h"
#include "zkit.h"

#include "instructions.h"
#include "platforms/backend-linux/memory-linux.h"

typedef enum _ARMInsnType {
    ARM_INS_ADD_register_A1,
    ARM_INS_LDR_literal_A1,
    ARM_INS_ADR_A1,
    ARM_INS_ADR_A2,
    ARM_INS_B_A1,
    ARM_INS_BLBLX_immediate_A1,
    ARM_INS_BLBLX_immediate_A2,
    ARM_UNDEF
} ARMInsnType;

#define MAX_INSN_SIZE 256
typedef struct _ARMReader {
    ARMInstruction *insnCTXs[MAX_INSN_SIZE];
    zz_size_t insnCTXs_count;
    zz_addr_t start_pc;
    zz_addr_t insns_buffer;
    zz_size_t insns_size;
} ARMReader;

ARMInsnType GetARMInsnType(uint32_t insn);

ARMReader *arm_reader_new(zz_ptr_t insn_address);
void arm_reader_init(ARMReader *self, zz_ptr_t insn_address);
void arm_reader_reset(ARMReader *self, zz_ptr_t insn_address);
void arm_reader_free(ARMReader *self);
ARMInstruction *arm_reader_read_one_instruction(ARMReader *self);

#endif