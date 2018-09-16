#ifndef ZZ_ARCH_ARM_CONSTANTS_H_
#define ZZ_ARCH_ARM_CONSTANTS_H_

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

// -----------------------------------------------------------------------------
// Conditions.

// Defines constants and accessor classes to assemble, disassemble and
// simulate ARM instructions.
//
// Section references in the code refer to the "ARM Architecture Reference
// Manual" from July 2005 (available at http://www.arm.com/miscPDFs/14128.pdf)
//
// Constants for specific fields are defined in their respective named enums.
// General constants are in an anonymous enum in class Instr.

// Values for the condition field as defined in section A3.2
enum Condition {
  kNoCondition = -1,

  EQ = 0 << 28,  // Z set            Equal.
  ne = 1 << 28,  // Z clear          Not equal.
  cs = 2 << 28,  // C set            Unsigned higher or same.
  cc = 3 << 28,  // C clear          Unsigned lower.
  mi = 4 << 28,  // N set            Negative.
  pl = 5 << 28,  // N clear          Positive or zero.
  vs = 6 << 28,  // V set            Overflow.
  vc = 7 << 28,  // V clear          No overflow.
  hi = 8 << 28,  // C set, Z clear   Unsigned higher.
  ls = 9 << 28,  // C clear or Z set Unsigned lower or same.
  ge = 10 << 28, // N == V           Greater or equal.
  lt = 11 << 28, // N != V           Less than.
  gt = 12 << 28, // Z clear, N == V  Greater than.
  le = 13 << 28, // Z set or N != V  Less then or equal
  al = 14 << 28, //                  Always.

  kSpecialCondition   = 15 << 28, // Special condition (refer to section A3.2.1).
  kNumberOfConditions = 16,

  // Aliases.
  hs = cs, // C set            Unsigned higher or same.
  lo = cc  // C clear          Unsigned lower.
};

#endif