#ifndef platforms_arch_arm_reader_arm_h
#define platforms_arch_arm_reader_arm_h

#include "hookzz.h"
#include "kitzz.h"

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
typedef struct _ZzARMReader {
    ZzARMInstruction *insns[MAX_INSN_SIZE];
    zz_size_t insn_size;
    zz_addr_t r_start_address;
    zz_addr_t r_current_address;
    zz_addr_t start_pc;
    zz_addr_t current_pc;
    zz_size_t size;
} ZzARMReader;

ARMInsnType GetARMInsnType(uint32_t insn);

ZzARMReader *zz_arm_reader_new(zz_ptr_t insn_address);
void zz_arm_reader_init(ZzARMReader *self, zz_ptr_t insn_address);
void zz_arm_reader_reset(ZzARMReader *self, zz_ptr_t insn_address);
void zz_arm_reader_free(ZzARMReader *self);
ZzARMInstruction *zz_arm_reader_read_one_instruction(ZzARMReader *self);

#endif