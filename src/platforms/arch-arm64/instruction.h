#ifndef platforms_arch_arm64_instruction_h
#define platforms_arch_arm64_instruction_h

#include "hookzz.h"

typedef struct _ARM64InstructionCTX {
  zz_addr_t pc;
  void *buffer;
  uint8_t size;
  uint32_t bytes;
} ARM64InstructionCTX;

#endif
