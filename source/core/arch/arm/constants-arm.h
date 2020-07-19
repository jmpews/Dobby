#ifndef CORE_ARCH_CONSTANTS_ARM_H
#define CORE_ARCH_CONSTANTS_ARM_H

// Memory operand addressing mode.
enum AddrMode {
    // Bit encoding P U W.
    Offset       = (8 | 4 | 0) << 21, // Offset (without writeback to base).
    PreIndex     = (8 | 4 | 1) << 21, // Pre-indexed addressing with writeback.
    PostIndex    = (0 | 4 | 0) << 21, // Post-indexed addressing with writeback.
    NegOffset    = (8 | 0 | 0) << 21, // Negative offset (without writeback to base).
    NegPreIndex  = (8 | 0 | 1) << 21, // Negative pre-indexed with writeback.
    NegPostIndex = (0 | 0 | 0) << 21  // Negative post-indexed with writeback.
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

enum {
  B0  = 1 << 0,
  B4  = 1 << 4,
  B5  = 1 << 5,
  B6  = 1 << 6,
  B7  = 1 << 7,
  B8  = 1 << 8,
  B9  = 1 << 9,
  B10 = 1 << 10,
  B12 = 1 << 12,
  B14 = 1 << 14,
  B16 = 1 << 16,
  B17 = 1 << 17,
  B18 = 1 << 18,
  B19 = 1 << 19,
  B20 = 1 << 20,
  B21 = 1 << 21,
  B22 = 1 << 22,
  B23 = 1 << 23,
  B24 = 1 << 24,
  B25 = 1 << 25,
  B26 = 1 << 26,
  B27 = 1 << 27,
  B28 = 1 << 28,
};

enum InstructionFields {
    kConditionShift = 28,
};

#endif