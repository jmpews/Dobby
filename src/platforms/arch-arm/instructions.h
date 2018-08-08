#ifndef platforms_arch_arm_instructions_h
#define platforms_arch_arm_instructions_h

#include "hookzz.h"
#include "zkit.h"

  typedef enum {
    eEncodingA1,
    eEncodingA2,
    eEncodingA3,
    eEncodingA4,
    eEncodingA5,
    eEncodingT1,
    eEncodingT2,
    eEncodingT3,
    eEncodingT4,
    eEncodingT5
  } ARMEncoding;

typedef struct _ARMInstruction {
  EncodingType type;
  zz_addr_t pc;
  zz_addr_t address;
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

static uint32_t get_insn_sub(uint32_t insn, int start, int length);
#endif