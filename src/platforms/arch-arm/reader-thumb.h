#ifndef platforms_arch_thumb_reader_thumb_h
#define platforms_arch_thumb_reader_thumb_h

#include "hookzz.h"
#include "zkit.h"

#include "instructions.h"
#include "reader-arm.h"

typedef enum _THUMBInsnType {
    THUMB_INS_CBNZ_CBZ,
    THUMB_INS_ADD_register_T2,
    THUMB_INS_LDR_literal_T1,
    THUMB_INS_LDR_literal_T2,
    THUMB_INS_ADR_T1,
    THUMB_INS_ADR_T2,
    THUMB_INS_ADR_T3,
    THUMB_INS_B_T1,
    THUMB_INS_B_T2,
    THUMB_INS_B_T3,
    THUMB_INS_B_T4,
    THUMB_INS_BLBLX_immediate_T1,
    THUMB_INS_BLBLX_immediate_T2,
    THUMB_UNDEF
} THUMBInsnType;

THUMBInsnType GetTHUMBInsnType(uint16_t insn1, uint16_t insn2);
ARMReader *zz_thumb_reader_new(zz_ptr_t insn_address);
void zz_thumb_reader_init(ARMReader *self, zz_ptr_t insn_address);
void zz_thumb_reader_reset(ARMReader *self, zz_ptr_t insn_address);
void zz_thumb_reader_free(ARMReader *self);
ARMInstruction *zz_thumb_reader_read_one_instruction(ARMReader *self);
#endif