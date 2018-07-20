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

ARMInstructionX ARMInstArrary[32]      = {0};
ThumbInstructionX Thumb2InstArrary[32] = {0};
Thumb2InstructionX ThumbInstArrary[32] = {0};

__attribute__((constructor)) void initializeARMInstructionX() {
  // initialize ARM
  ARMInstArrary[LoadLiteral]   = (ARM64InstructionX){0 | 0b011 << 27 | 0b00 << 24, 0 | 0b111 << 27 | 0b11 << 24};
  ARMInstArrary[BaseCmpBranch] = (ARM64InstructionX){0 | 0b011010 << 25, 0b111111 << 25};
  ARMInstArrary[BranchCond]    = (ARM64InstructionX){0 | 0b01010100 << 24 | 0 << 4, 0 | 0b11111111 << 24 | 1 << 4};
  ARMInstArrary[B]             = (ARM64InstructionX){0 | 0 << 31 | 0b00101 << 26, 0 | 1 << 31 | 0b11111 << 26};
  ARMInstArrary[BL]            = (ARM64InstructionX){0 | 1 << 31 | 0b00101 << 26, 0 | 1 << 31 | 0b11111 << 26};

  // initialize Thumb2
  Thumb2InstArrary[t2ADR] = (Thumb2InstructionX){};
}
