//
// Created by jmpews on 2018/6/14.
//

#ifndef HOOKZZ_INSTRUCTION_H
#define HOOKZZ_INSTRUCTION_H

#include "hookzz.h"

typedef struct _ARM64InstructionCTX {
  zz_addr_t pc;
  zz_addr_t address;
  uint8_t size;
  uint32_t bytes;
} ARM64InstructionCTX;

#endif //HOOKZZ_INSTRUCTION_H
