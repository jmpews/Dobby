#ifndef platforms_arch_arm_instructions_h
#define platforms_arch_arm_instructions_h

#include "hookzz.h"

typedef enum { ThumbEncoding, Thumb2Encoding, ARMEncoding } InstEncodingType;

typedef struct _ARMInstructionCTX {
  InstEncodingType type;
  zz_addr_t pc;
  void *buffer;
  uint8_t size;
  union {
    uint32_t trick_insn;
    struct {
      uint16_t trick_insn1;
      uint16_t trick_insn2;
    };
  };

  uint32_t insn;
  uint16_t insn1;
  uint16_t insn2;
} ARMInstruction;

#endif