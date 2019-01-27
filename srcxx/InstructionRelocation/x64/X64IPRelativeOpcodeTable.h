#ifndef HOOKZZ_X64IPRELATIVEOPCODETABLE_H
#define HOOKZZ_X64IPRELATIVEOPCODETABLE_H

enum OperandType {
  UNSET_OP_ORDER = 0,
  // Operand size decides between 16, 32 and 64 bit operands.
  REG_OPER_OP_ORDER = 1, // Register destination, operand source.
  OPER_REG_OP_ORDER = 2, // Operand destination, register source.
                         // Fixed 8-bit operands.
  BYTE_SIZE_OPERAND_FLAG = 4,
  BYTE_REG_OPER_OP_ORDER = REG_OPER_OP_ORDER | BYTE_SIZE_OPERAND_FLAG,
  BYTE_OPER_REG_OP_ORDER = OPER_REG_OP_ORDER | BYTE_SIZE_OPERAND_FLAG
};

#define Op2RA(name) relo_##name_2_reg_op
#define Op2AR(name) relo_##name_2_op_reg
#define OpB2RA(name) relo_##name_byte_2_reg_op
#define OpB2AR(name) relo_##name_byte_2_op_reg

struct OpMnemonic {
  int opcode;
  OperandType op_order_;
};

#define OP_LIST_B2AR_2AR_B2RA_2RA(name, op1, op2, op3, op4)                                                            \
  Op2RA(name) = op1, Op2AR(name) = op2, OpB2RA(name) = op3, OpB2AR(name) = op4,

// clang-format off
enum relo_two_operands_instr {
  OP_LIST_B2AR_2AR_B2RA_2RA(add, 0x00, 0x01, 0x02, 0x03)
  OP_LIST_B2AR_2AR_B2RA_2RA(or, 0x00, 0x01, 0x02, 0x03)
  OP_LIST_B2AR_2AR_B2RA_2RA(adc, 0x00, 0x01, 0x02, 0x03)
  OP_LIST_B2AR_2AR_B2RA_2RA(sbb, 0x00, 0x01, 0x02, 0x03)
  OP_LIST_B2AR_2AR_B2RA_2RA(and, 0x00, 0x01, 0x02, 0x03)
  OP_LIST_B2AR_2AR_B2RA_2RA(sub, 0x00, 0x01, 0x02, 0x03)
  OP_LIST_B2AR_2AR_B2RA_2RA(xor, 0x00, 0x01, 0x02, 0x03)
  OP_LIST_B2AR_2AR_B2RA_2RA(cmp, 0x00, 0x01, 0x02, 0x03)
  OpB2RA(test) = 0x84,
  Op2RA(test) = 0x85,
  OpB2RA(xchg) = 0x86,
  Op2RA(xchg) = 0x87,
};

enum call_jump_instr {
  relo_call = 0xE8,
  relo_jmp = 0xE9
};


#define PREFIX_SEGMENT_CS   0x2e
#define PREFIX_SEGMENT_SS   0x36
#define PREFIX_SEGMENT_DS   0x3e
#define PREFIX_SEGMENT_ES   0x26
#define PREFIX_SEGMENT_FS   0x64
#define PREFIX_SEGMENT_GS   0x65
#define PREFIX_LOCK         0xf0
#define PREFIX_REPNZ        0xf2
#define PREFIX_REPX         0xf3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67

struct InstrMnemonic {
  uint8_t prefix;
};

struct OpcodeItem {
  int opcode; // ignored, same as table index
}

void decode_prefix(InstrMnemonic *instr, byte _prefix) {
  instr->prefix = _prefix;
}

struct OpcodeItem OpcodeHandlerTable[] = {
  {0x00, },
  {0x26, decode_prefix},
  {0x2E, decode_prefix},
  {0x36, decode_prefix},
  {0x3E, decode_prefix},
  {0x64, decode_prefix},
  {0x65, decode_prefix},

};

// clang-format on
#endif //HOOKZZ_X64IPRELATIVEOPCODETABLE_H
