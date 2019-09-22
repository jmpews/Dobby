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

// Values for the condition field as defined in section A3.2.
enum Condition {
  kNoCondition        = -1,
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
  kSpecialCondition   = 15, // special condition (refer to section A3.2.1)
  kNumberOfConditions = 16,

};

// Opcodes for Data-processing instructions (instructions with a type 0 and 1)
// as defined in section A3.4
enum Opcode {
  kNoOperand  = -1,
  AND         = 0,  // Logical AND
  EOR         = 1,  // Logical Exclusive OR
  SUB         = 2,  // Subtract
  RSB         = 3,  // Reverse Subtract
  ADD         = 4,  // Add
  ADC         = 5,  // Add with Carry
  SBC         = 6,  // Subtract with Carry
  RSC         = 7,  // Reverse Subtract with Carry
  TST         = 8,  // Test
  TEQ         = 9,  // Test Equivalence
  CMP         = 10, // Compare
  CMN         = 11, // Compare Negated
  ORR         = 12, // Logical (inclusive) OR
  MOV         = 13, // Move
  BIC         = 14, // Bit Clear
  MVN         = 15, // Move Not
  kMaxOperand = 16
};

// Shifter types for Data-processing operands as defined in section A5.1.2.
enum Shift {
  kNoShift  = -1,
  LSL       = 0, // Logical shift left
  LSR       = 1, // Logical shift right
  ASR       = 2, // Arithmetic shift right
  ROR       = 3, // Rotate right
  kMaxShift = 4
};

// Constants used for the decoding or encoding of the individual fields of
// instructions. Based on the "Figure 3-1 ARM instruction set summary".
enum InstructionFields {
  kConditionShift = 28,
  kConditionBits  = 4,
  kTypeShift      = 25,
  kTypeBits       = 3,
  kLinkShift      = 24,
  kLinkBits       = 1,
  kUShift         = 23,
  kUBits          = 1,
  kOpcodeShift    = 21,
  kOpcodeBits     = 4,
  kSShift         = 20,
  kSBits          = 1,
  kRnShift        = 16,
  kRnBits         = 4,
  kRdShift        = 12,
  kRdBits         = 4,
  kRsShift        = 8,
  kRsBits         = 4,
  kRmShift        = 0,
  kRmBits         = 4,

  // Immediate instruction fields encoding.
  kRotateShift = 8,
  kRotateBits  = 4,
  kImmed8Shift = 0,
  kImmed8Bits  = 8,

  // Shift instruction register fields encodings.
  kShiftImmShift      = 7,
  kShiftRegisterShift = 8,
  kShiftImmBits       = 5,
  kShiftShift         = 5,
  kShiftBits          = 2,
};

// Instruction encoding bits and masks.
enum {
  H   = 1 << 5,  // Halfword (or byte).
  S6  = 1 << 6,  // Signed (or unsigned).
  L   = 1 << 20, // Load (or store).
  S   = 1 << 20, // Set condition code (or leave unchanged).
  W   = 1 << 21, // Writeback base register (or leave unchanged).
  A   = 1 << 21, // Accumulate in multiply instruction (or not).
  B   = 1 << 22, // Unsigned byte (or word).
  N   = 1 << 22, // Long (or short).
  U   = 1 << 23, // Positive (or negative) offset/index.
  P   = 1 << 24, // Offset/pre-indexed addressing (or post-indexed addressing).
  I   = 1 << 25, // Immediate shifter operand (or not).
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

#endif