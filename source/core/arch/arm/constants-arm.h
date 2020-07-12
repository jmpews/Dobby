#ifndef CORE_ARCH_CONSTANTS_ARM_H
#define CORE_ARCH_CONSTANTS_ARM_H

// Memory operand addressing mode.
enum AddrMode {
  // Bit encoding P U W.
  Offset       = 1, // Offset (without writeback to base).
  PreIndex     = 2, // Pre-indexed addressing with writeback.
  PostIndex    = 3, // Post-indexed addressing with writeback.
};

enum Condition {
  EQ                  = 0,  // equal
  NE                  = 1,  // not equal
  CS                  = 2,  // carry set/unsigned higher or same
  CC                  = 3,  // carry clear/unsigned lower
  MI                  = 4,  // minus/negative
  PL                  = 5,  // plus/positive or zero
  VS                  = 6,  // overflow
  VC                  = 7,  // no overflow
  HI                  = 8,  // unsigned higher
  LS                  = 9,  // unsigned lower or same
  GE                  = 10, // signed greater than or equal
  LT                  = 11, // signed less than
  GT                  = 12, // signed greater than
  LE                  = 13, // signed less than or equal
  AL                  = 14, // always (unconditional)

};

enum Shift {
  LSL       = 0, // Logical shift left
  LSR       = 1, // Logical shift right
  ASR       = 2, // Arithmetic shift right
  ROR       = 3, // Rotate right
};

#endif