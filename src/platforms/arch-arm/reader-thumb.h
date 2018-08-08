#ifndef platforms_arch_thumb_reader_thumb_h
#define platforms_arch_thumb_reader_thumb_h

#include "hookzz.h"
#include "zkit.h"

#include "instructions.h"
#include "reader-arm.h"

typedef enum _ThumbInsnType {
    thumb_1_cbnz_cbz = 0,
    thumb_1_comparebranch = 0,
    thumb_1_b_T1 = 1,
    thumb_1_conditionalbranch = 1,
    thumb_
    Thumb_INS_LDR_literal_T1,
    Thumb_INS_LDR_literal_T2,
    Thumb_INS_ADR_T1,
    Thumb_INS_ADR_T2,
    Thumb_INS_ADR_T3,
    Thumb_INS_B_T1,
    Thumb_INS_B_T2,
    Thumb_INS_B_T3,
    Thumb_INS_B_T4,
    Thumb_INS_BLBLX_immediate_T1,
    Thumb_INS_BLBLX_immediate_T2,
    Thumb_UNDEF
} ThumbInsnType;

struct

ThumbInstType decodeInstructionType(uint32_t inst_32) {

}

#endif