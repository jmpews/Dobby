//
// Created by jmpews on 2018/5/14.
//

#include "ARMAssemblyCore.h"

#define WORD_SIZE 4

inline void BIT32SET(uint32_t *inst32, int start, int len, uint32_t v) {
  if (!inst32)
    return;
  // *inst32 = *inst32 | (v << start);
  *inst32 = (*inst32 & ~(((1 << len) - 1) << start)) | (v << start);
}

inline void BIT32SETMASK(uint32_t *inst32, int start, int len) {
  if (!inst32)
    return;
  *inst32 = *inst32 | (((1 << len) - 1) << start);
}
inline void BIT32MASKSET(uint32_t *inst32, uint32_t *mask32, int start, int len, uint32_t v) {
  if (!inst32)
    return;
  *inst32 = *inst32 | (v << start);
  *mask32 = *mask32 | (((1 << len) - 1) << start);
}

inline void BIT32GET(uint32_t inst32, int start, int len, uint32_t *v) {
  if (!v)
    return;
  *v = (inst32 >> start) & ((1 << len) - 1);
}

ARMInstructionX ARMInstArrary[32]       = {0};
Thumb2InstructionX Thumb2InstArrary[32] = {0};
ThumbInstructionX ThumbInstArrary[32]   = {0};

// clang-format off
__attribute__((constructor)) void initializeARMInstructionX() {
  // initialize ARM
  ARMInstArrary[LoadLiteral]   = (ARM64InstructionX){0 | 0b011 << 27 | 0b00 << 24, 0 | 0b111 << 27 | 0b11 << 24};
  ARMInstArrary[BaseCmpBranch] = (ARM64InstructionX){0 | 0b011010 << 25, 0b111111 << 25};
  ARMInstArrary[BranchCond]    = (ARM64InstructionX){0 | 0b01010100 << 24 | 0 << 4, 0 | 0b11111111 << 24 | 1 << 4};
  ARMInstArrary[B]             = (ARM64InstructionX){0 | 0 << 31 | 0b00101 << 26, 0 | 1 << 31 | 0b11111 << 26};
  ARMInstArrary[BL]            = (ARM64InstructionX){0 | 1 << 31 | 0b00101 << 26, 0 | 1 << 31 | 0b11111 << 26};

  // initialize Thumb2
  // ARMInstrThumb2.td : def t2ADR
  Thumb2InstArrary[MULTICLASS_3(XI, T2PCOneRegImm, t2ADR)] =
      (Thumb2InstructionX){0 | 0b11110 << 27 | 0b10 << 24 | 0b0 << 22 | 0b0 << 20 | 0b1111 << 16 | 0b0 << 15,
                           0 | 0b11111 << 27 | 0b11 << 24 | 0b1 << 22 | 0b1 << 20 | 0b1111 << 16 | 0b1 << 15};

  // initialize Thumb
  // ARMInstrThumb.td
  ThumbInstArrary[cclass_3_parent(tADR, T1I, T1Encoding, Sched)] = (ThumbInstructionX) {
      0 | 0b10100 << (10+1),
      0 | 0b11111 << (10+1)
    };

  ARMInstArrary[cclass_3_parent(tBcc, T1I, T1BranchCond, Sched)] = (ARMInstructionX) {
      0 | 0b1101 << 12,
      0 | 0b1111 << 12
    };

  ARMInstArrary[cclass_3_parent(tBL, TIx2, Requires, Sched)] = (ARMInstructionX) {
      0 | 0b11110 << 27 | 0b11 << 14 | 0b1 << 12,
      0 | 0b11111 << 27 | 0b11 << 14 | 0b1 << 12
    };

  ARMInstArrary[cclass_3_parent(tBL, TIx2, Requires, Sched)] = (ARMInstructionX) {
    0 | 0b11100 << (10+1),
    0 | 0b11111 << (10+1),
  };
}