#ifndef HOOKZZ_X64IPRELATIVEOPCODETABLE_H
#define HOOKZZ_X64IPRELATIVEOPCODETABLE_H

typedef unsigned long addr_t;
typedef char byte;

#define PREFIX_SEGMENT_CS 0x2e
#define PREFIX_SEGMENT_SS 0x36
#define PREFIX_SEGMENT_DS 0x3e
#define PREFIX_SEGMENT_ES 0x26
#define PREFIX_SEGMENT_FS 0x64
#define PREFIX_SEGMENT_GS 0x65
#define PREFIX_LOCK 0xf0
#define PREFIX_REPNZ 0xf2
#define PREFIX_REPX 0xf3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67

enum OpcodeType { OpTy_Op1, OpTy_RegInOp1, OpTy_Op1ExtraOp };

struct Instr {

  byte prefix;

  union {
    byte opcode[3];
    struct {
      byte opcode1;
      byte opcode2;
      byte opcode3;
    };
  };

  union {
    byte ModRM;
    struct {
      byte Mod;
      byte RegOpcode;
      byte RM;
    };
  };

  union {
    byte SIB;
    struct SIB {
      byte base;
      byte index;
      byte scale;
    };
  };

  byte Displacement[4];

  byte Immediate[4];
};

struct InstrMnemonic {
  uint len;

  OpcodeType OpTy;

  struct Instr instr;

};

// clang-format on
void _DecodePrefix(InstrMnemonic *instr, addr_t p) {
  instr->instr.prefix = *(byte *)p;

  instr->len++;
}

void _DecodeOp(InstrMnemonic *instr, addr_t p, OpcodeType OpTy) {
  instr->OpTy = OpTy;
  instr->instr.opcode1 = *(byte *)p;
  instr->len++;
}

void _DecodeModRM(InstrMnemonic *instr, addr_t p) {
}

void _DecodeSIB(InstrMnemonic *instr, addr_t p) {
}

void _Decode_Op_ModRM(InstrMnemonic *instr, addr_t p, OpcodeType OpTy) {
  _DecodeOp(instr, p, OpTy);
  _DecodeModRM(instr, p);
}

void _Decode_Op_ModRM_SIB(InstrMnemonic *instr, addr_t p, OpcodeType OpTy) {
  _DecodeOp(instr, p, OpTy);
  _DecodeModRM(instr, p);
  _DecodeSIB(instr, p);

}

void _DecodeOperand(InstrMnemonic *instr, addr_t p) {

}


enum OperandEncodingType { OpEn_ZO, OpEn_RM, OpEn_MR, OpEn_MI, OpEn_I, OpEn_RMI, OpEn_OI };

struct OpcodeDecodeItem {
  byte opcode;
  byte extra_opcode : 3;
  void *DecodeHandler;
};

void _DecodeOpEn_RM(InstrMnemonic *instr, addr_t p) {
  _Decode_Op_ModRM(instr, p, OpTy_Op1);
}

void _DecodeOpExtraOpEn_RM(InstrMnemonic *instr, addr_t p) {
  _Decode_Op_ModRM(instr, p, OpTy_Op1ExtraOp);
}

void _DecodeOpEn_I_8(InstrMnemonic *instr, addr_t p) {
  _Decode_Op_ModRM(instr, p, OpTy_Op1);
  _DecodeOperand(instr, p);
}

void _DecodeOpEn_I_16or32(InstrMnemonic *instr, addr_t p) {
  _Decode_Op_ModRM(instr, p, OpTy_Op1);

}
void _DecodeOpEn_ZO(InstrMnemonic *instr, addr_t p) {
  _DecodeOp(instr, p, OpTy_Op1);
}

// Decode By Operand Encoding
#define _xDecodeOpEn_RM 0, _DecodeOpEn_RM
#define _xDecodeOpExtraOpEn_RM 0, _DecodeOpExtraOpEn_RM
#define _xDecodeOpEn_I_8 0, _DecodeOpEn_I_8
#define _xDecodeOpEn_I_16or32 0, _DecodeOpEn_I_16or32

// Only the single opcode byte
#define _xDecodeOpEn_ZO 0, _DecodeOpEn_ZO

// Reg in the Opcode
#define _xDecodeOpEn_O 0, _DecodeOpEn_O

// Decode Segment Prefix
#define _xDecodeSegPrefix 0, _DecodePrefix

//
#define _xDecodeOpEn_RMI 0, _DecodeModRMImm
#define _xDecodeOpExtraOpEn_MI_16or32 0, _DecodeOp1ExtraOpModMImm
#define _xDecodeREXPrefix 0, _DecodePrefix
#define _xDecodeOpEn_D 0, _xDecodeOpEnImm

const OpcodeDecodeItem OpcodeDecodeTable[257] = {
    {0x00, _xDecodeOpEn_RM},       // ADD /r
    {0x01, _xDecodeOpEn_RM},       // ADD /r
    {0x02, _xDecodeOpEn_RM},       // ADD /r
    {0x03, _xDecodeOpEn_RM},       // ADD /r
    {0x04, _xDecodeOpEn_I_8},      // ADD ib
    {0x05, _xDecodeOpEn_I_16or32}, // ADD iw
#ifdef DETOURS_X64
    {0x06, _InvalidCopy}, // Invalid
    {0x07, _InvalidCopy}, // Invalid
#else
    {0x06, _xDecodeOpEn_ZO},           // PUSH
    {0x07, _xDecodeOpEn_ZO},           // POP
#endif
    {0x08, _xDecodeOpEn_RM},       // OR /r
    {0x09, _xDecodeOpEn_RM},       // OR /r
    {0x0A, _xDecodeOpEn_RM},       // OR /r
    {0x0B, _xDecodeOpEn_RM},       // OR /r
    {0x0C, _xDecodeOpEn_I_8},      // OR ib
    {0x0D, _xDecodeOpEn_I_16or32}, // OR iw
#ifdef DETOURS_X64
    {0x0E, _InvalidCopy}, // Invalid
#else
    {0x0E, _xDecodeOpEn_ZO},           // PUSH
#endif
    {0x0F, _Copy0F},               // Extension Ops
    {0x10, _xDecodeOpEn_RM},       // ADC /r
    {0x11, _xDecodeOpEn_RM},       // ADC /r
    {0x12, _xDecodeOpEn_RM},       // ADC /r
    {0x13, _xDecodeOpEn_RM},       // ADC /r
    {0x14, _xDecodeOpEn_I_8},      // ADC ib
    {0x15, _xDecodeOpEn_I_16or32}, // ADC id
#ifdef DETOURS_X64
    {0x16, _InvalidCopy}, // Invalid
    {0x17, _InvalidCopy}, // Invalid
#else
    {0x16, _xDecodeOpEn_ZO},           // PUSH
    {0x17, _xDecodeOpEn_ZO},           // POP
#endif
    {0x18, _xDecodeOpEn_RM},       // SBB /r
    {0x19, _xDecodeOpEn_RM},       // SBB /r
    {0x1A, _xDecodeOpEn_RM},       // SBB /r
    {0x1B, _xDecodeOpEn_RM},       // SBB /r
    {0x1C, _xDecodeOpEn_I_8},      // SBB ib
    {0x1D, _xDecodeOpEn_I_16or32}, // SBB id
#ifdef DETOURS_X64
    {0x1E, _InvalidCopy}, // Invalid
    {0x1F, _InvalidCopy}, // Invalid
#else
    {0x1E, _xDecodeOpEn_ZO},           // PUSH
    {0x1F, _xDecodeOpEn_ZO},           // POP
#endif
    {0x20, _xDecodeOpEn_RM},       // AND /r
    {0x21, _xDecodeOpEn_RM},       // AND /r
    {0x22, _xDecodeOpEn_RM},       // AND /r
    {0x23, _xDecodeOpEn_RM},       // AND /r
    {0x24, _xDecodeOpEn_I_8},      // AND ib
    {0x25, _xDecodeOpEn_I_16or32}, // AND id
    {0x26, _xDecodeSegPrefix},     // ES prefix
#ifdef DETOURS_X64
    {0x27, _InvalidCopy}, // Invalid
#else
    {0x27, _xDecodeOpEn_ZO},           // DAA
#endif
    {0x28, _xDecodeOpEn_RM},       // SUB /r
    {0x29, _xDecodeOpEn_RM},       // SUB /r
    {0x2A, _xDecodeOpEn_RM},       // SUB /r
    {0x2B, _xDecodeOpEn_RM},       // SUB /r
    {0x2C, _xDecodeOpEn_I_8},      // SUB ib
    {0x2D, _xDecodeOpEn_I_16or32}, // SUB id
    {0x2E, _xDecodeSegPrefix},     // CS prefix
#ifdef DETOURS_X64
    {0x2F, _InvalidCopy}, // Invalid
#else
    {0x2F, _xDecodeOpEn_ZO},           // DAS
#endif
    {0x30, _xDecodeOpEn_RM},       // XOR /r
    {0x31, _xDecodeOpEn_RM},       // XOR /r
    {0x32, _xDecodeOpEn_RM},       // XOR /r
    {0x33, _xDecodeOpEn_RM},       // XOR /r
    {0x34, _xDecodeOpEn_I_8},      // XOR ib
    {0x35, _xDecodeOpEn_I_16or32}, // XOR id
    {0x36, _xDecodeSegPrefix},     // SS prefix
#ifdef DETOURS_X64
    {0x37, _InvalidCopy}, // Invalid
#else
    {0x37, _xDecodeOpEn_ZO},           // AAA
#endif
    {0x38, _xDecodeOpEn_RM},       // CMP /r
    {0x39, _xDecodeOpEn_RM},       // CMP /r
    {0x3A, _xDecodeOpEn_RM},       // CMP /r
    {0x3B, _xDecodeOpEn_RM},       // CMP /r
    {0x3C, _xDecodeOpEn_I_8},      // CMP ib
    {0x3D, _xDecodeOpEn_I_16or32}, // CMP id
    {0x3E, _xDecodeSegPrefix},     // DS prefix
#ifdef DETOURS_X64
    {0x3F, _InvalidCopy}, // Invalid
#else
    {0x3F, _xDecodeOpEn_ZO},           // AAS
#endif
#ifdef DETOURS_X64             // For REX Prefix
    {0x40, _xDecodeREXPrefix}, // REX
    {0x41, _xDecodeREXPrefix}, // REX
    {0x42, _xDecodeREXPrefix}, // REX
    {0x43, _xDecodeREXPrefix}, // REX
    {0x44, _xDecodeREXPrefix}, // REX
    {0x45, _xDecodeREXPrefix}, // REX
    {0x46, _xDecodeREXPrefix}, // REX
    {0x47, _xDecodeREXPrefix}, // REX
    {0x48, _xDecodeREXPrefix}, // REX
    {0x49, _xDecodeREXPrefix}, // REX
    {0x4A, _xDecodeREXPrefix}, // REX
    {0x4B, _xDecodeREXPrefix}, // REX
    {0x4C, _xDecodeREXPrefix}, // REX
    {0x4D, _xDecodeREXPrefix}, // REX
    {0x4E, _xDecodeREXPrefix}, // REX
    {0x4F, _xDecodeREXPrefix}, // REX
#else
    {0x40, _xDecodeOpEn_O},        // INC
    {0x41, _xDecodeOpEn_O},        // INC
    {0x42, _xDecodeOpEn_O},        // INC
    {0x43, _xDecodeOpEn_O},        // INC
    {0x44, _xDecodeOpEn_O},        // INC
    {0x45, _xDecodeOpEn_O},        // INC
    {0x46, _xDecodeOpEn_O},        // INC
    {0x47, _xDecodeOpEn_O},        // INC
    {0x48, _xDecodeOpEn_O},        // DEC
    {0x49, _xDecodeOpEn_O},        // DEC
    {0x4A, _xDecodeOpEn_O},        // DEC
    {0x4B, _xDecodeOpEn_O},        // DEC
    {0x4C, _xDecodeOpEn_O},        // DEC
    {0x4D, _xDecodeOpEn_O},        // DEC
    {0x4E, _xDecodeOpEn_O},        // DEC
    {0x4F, _xDecodeOpEn_O},        // DEC
#endif
    {0x50, _xDecodeOpEn_O}, // PUSH
    {0x51, _xDecodeOpEn_O}, // PUSH
    {0x52, _xDecodeOpEn_O}, // PUSH
    {0x53, _xDecodeOpEn_O}, // PUSH
    {0x54, _xDecodeOpEn_O}, // PUSH
    {0x55, _xDecodeOpEn_O}, // PUSH
    {0x56, _xDecodeOpEn_O}, // PUSH
    {0x57, _xDecodeOpEn_O}, // PUSH
    {0x58, _xDecodeOpEn_O}, // POP
    {0x59, _xDecodeOpEn_O}, // POP
    {0x5A, _xDecodeOpEn_O}, // POP
    {0x5B, _xDecodeOpEn_O}, // POP
    {0x5C, _xDecodeOpEn_O}, // POP
    {0x5D, _xDecodeOpEn_O}, // POP
    {0x5E, _xDecodeOpEn_O}, // POP
    {0x5F, _xDecodeOpEn_O}, // POP
#ifdef DETOURS_X64
    {0x60, _InvalidCopy}, // Invalid
    {0x61, _InvalidCopy}, // Invalid
    {0x62, _InvalidCopy}, // Invalid (not yet implemented Intel EVEX support)
#else
    {0x60, _xDecodeOpEn_ZO},           // PUSHAD
    {0x61, _xDecodeOpEn_ZO},           // POPAD
    {0x62, _xDecodeOpEn_RM},       // BOUND /r
#endif
    {0x63, _xDecodeOpEn_RM},            // 32bit ARPL /r, 64bit MOVSXD
    {0x64, _xDecodeSegPrefix},          // FS prefix
    {0x65, _xDecodeSegPrefix},          // GS prefix
    {0x66, _Copy66},                    // Operand Prefix
    {0x67, _Copy67},                    // Address Prefix
    {0x68, _xDecodeOpEn_I_16or32},      // PUSH
    {0x69, _xDecodeOpEn_RMI},           // IMUL /r iz
    {0x6A, _xDecodeOpEn_I_8},           // PUSH
    {0x6B, _xDecodeOpModRMImm8},        // IMUL /r ib
    {0x6C, _xDecodeOpEn_ZO},                // INS
    {0x6D, _xDecodeOpEn_ZO},                // INS
    {0x6E, _xDecodeOpEn_ZO},                // OUTS/OUTSB
    {0x6F, _xDecodeOpEn_ZO},                // OUTS/OUTSW
    {0x70, _xDecodeOpEn_D},             // JO           // 0f80
    {0x71, _xDecodeOpEn_D},             // JNO          // 0f81
    {0x72, _xDecodeOpEn_D},             // JB/JC/JNAE   // 0f82
    {0x73, _xDecodeOpEn_D},             // JAE/JNB/JNC  // 0f83
    {0x74, _xDecodeOpEn_D},             // JE/JZ        // 0f84
    {0x75, _xDecodeOpEn_D},             // JNE/JNZ      // 0f85
    {0x76, _xDecodeOpEn_D},             // JBE/JNA      // 0f86
    {0x77, _xDecodeOpEn_D},             // JA/JNBE      // 0f87
    {0x78, _xDecodeOpEn_D},             // JS           // 0f88
    {0x79, _xDecodeOpEn_D},             // JNS          // 0f89
    {0x7A, _xDecodeOpEn_D},             // JP/JPE       // 0f8a
    {0x7B, _xDecodeOpEn_D},             // JNP/JPO      // 0f8b
    {0x7C, _xDecodeOpEn_D},             // JL/JNGE      // 0f8c
    {0x7D, _xDecodeOpEn_D},             // JGE/JNL      // 0f8d
    {0x7E, _xDecodeOpEn_D},             // JLE/JNG      // 0f8e
    {0x7F, _xDecodeOpEn_D},             // JG/JNLE      // 0f8f
    {0x80, _xDecodeOp1ExtraOpModMImm8}, // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 byte reg, immediate byte
    {0x81,
     _xDecodeOpExtraOpEn_MI_16or32}, // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 byte reg, immediate word or dword
#ifdef DETOURS_X64
    {0x82, _InvalidCopy}, // Invalid
#else
    {0x82, _Unknown},              // MOV al,x
#endif
    {0x83, _xDecodeOp1ExtraOpModMImm8}, // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 reg, immediate byte
    {0x84, _xDecodeOpEn_RM},            // TEST /r
    {0x85, _xDecodeOpEn_RM},            // TEST /r
    {0x86, _xDecodeOpEn_RM},            // XCHG /r @todo
    {0x87, _xDecodeOpEn_RM},            // XCHG /r @todo
    {0x88, _xDecodeOpEn_RM},            // MOV /r
    {0x89, _xDecodeOpEn_RM},            // MOV /r
    {0x8A, _xDecodeOpEn_RM},            // MOV /r
    {0x8B, _xDecodeOpEn_RM},            // MOV /r
    {0x8C, _xDecodeOpEn_RM},            // MOV /r
    {0x8D, _xDecodeOpEn_RM},            // LEA /r
    {0x8E, _xDecodeOpEn_RM},            // MOV /r
    {0x8F, _xDecodeOpEn_RM},            // POP /0
    {0x90, _xDecodeOpEn_ZO},                // NOP
    {0x91, _xDecodeOpEn_ZO},                // XCHG
    {0x92, _xDecodeOpEn_ZO},                // XCHG
    {0x93, _xDecodeOpEn_ZO},                // XCHG
    {0x94, _xDecodeOpEn_ZO},                // XCHG
    {0x95, _xDecodeOpEn_ZO},                // XCHG
    {0x96, _xDecodeOpEn_ZO},                // XCHG
    {0x97, _xDecodeOpEn_ZO},                // XCHG
    {0x98, _xDecodeOpEn_ZO},                // CWDE
    {0x99, _xDecodeOpEn_ZO},                // CDQ
#ifdef DETOURS_X64
    {0x9A, _InvalidCopy}, // Invalid
#else
    {0x9A, _CopyBytes5Or7Dynamic}, // CALL cp
#endif
    {0x9B, _xDecodeOpEn_ZO},                   // WAIT/FWAIT
    {0x9C, _xDecodeOpEn_ZO},                   // PUSHFD
    {0x9D, _xDecodeOpEn_ZO},                   // POPFD
    {0x9E, _xDecodeOpEn_ZO},                   // SAHF
    {0x9F, _xDecodeOpEn_ZO},                   // LAHF
    {0xA0, _Unknwon},                      // MOV
    {0xA1, _Unknwon},                      // MOV
    {0xA2, _Unknwon},                      // MOV
    {0xA3, _Unknwon},                      // MOV
    {0xA4, _xDecodeOpEn_ZO},                   // MOVS
    {0xA5, _xDecodeOpEn_ZO},                   // MOVS/MOVSD
    {0xA6, _xDecodeOpEn_ZO},                   // CMPS/CMPSB
    {0xA7, _xDecodeOpEn_ZO},                   // CMPS/CMPSW
    {0xA8, _xDecodeOpEn_I_8},              // TEST
    {0xA9, _xDecodeOpEn_I_16or32},         // TEST
    {0xAA, _xDecodeOpEn_ZO},                   // STOS/STOSB
    {0xAB, _xDecodeOpEn_ZO},                   // STOS/STOSW
    {0xAC, _xDecodeOpEn_ZO},                   // LODS/LODSB
    {0xAD, _xDecodeOpEn_ZO},                   // LODS/LODSW
    {0xAE, _xDecodeOpEn_ZO},                   // SCAS/SCASB
    {0xAF, _xDecodeOpEn_ZO},                   // SCAS/SCASD
    {0xB0, _xDecodeRegInOpImm8},           // MOV B0+rb
    {0xB1, _xDecodeRegInOpImm8},           // MOV B0+rb
    {0xB2, _xDecodeRegInOpImm8},           // MOV B0+rb
    {0xB3, _xDecodeRegInOpImm8},           // MOV B0+rb
    {0xB4, _xDecodeRegInOpImm8},           // MOV B0+rb
    {0xB5, _xDecodeRegInOpImm8},           // MOV B0+rb
    {0xB6, _xDecodeRegInOpImm8},           // MOV B0+rb
    {0xB7, _xDecodeRegInOpImm8},           // MOV B0+rb
    {0xB8, _xDecodeRegInOpImm16or32},      // MOV B8+rb
    {0xB9, _xDecodeRegInOpImm16or32},      // MOV B8+rb
    {0xBA, _xDecodeRegInOpImm16or32},      // MOV B8+rb
    {0xBB, _xDecodeRegInOpImm16or32},      // MOV B8+rb
    {0xBC, _xDecodeRegInOpImm16or32},      // MOV B8+rb
    {0xBD, _xDecodeRegInOpImm16or32},      // MOV B8+rb
    {0xBE, _xDecodeRegInOpImm16or32},      // MOV B8+rb
    {0xBF, _xDecodeRegInOpImm16or32},      // MOV B8+rb
    {0xC0, _xDecodeOp1ExtraOpModMImm8},    // RCL/2 ib, etc.
    {0xC1, _xDecodeOp1ExtraOpModMImm8},    // RCL/2 ib, etc.
    {0xC2, _CopyBytes3},                   // RET
    {0xC3, _xDecodeOpEn_ZO},                   // RET
    {0xC4, _CopyVex3},                     // LES, VEX 3-byte opcodes.
    {0xC5, _CopyVex2},                     // LDS, VEX 2-byte opcodes.
    {0xC6, _Unknown},                      // MOV
    {0xC7, _xDecodeOpExtraOpEn_MI_16or32}, // MOV/0 XBEGIN/7
    {0xC8, _CopyBytes4},                   // ENTER
    {0xC9, _xDecodeOpEn_ZO},                   // LEAVE
    {0xCA, _CopyBytes3Dynamic},            // RET
    {0xCB, _CopyBytes1Dynamic},            // RET
    {0xCC, _CopyBytes1Dynamic},            // INT 3
    {0xCD, _CopyBytes2Dynamic},            // INT ib
#ifdef DETOURS_X64
    {0xCE, _InvalidCopy}, // Invalid
#else
    {0xCE, _CopyBytes1Dynamic},    // INTO
#endif
    {0xCF, _CopyBytes1Dynamic}, // IRET
    {0xD0, _xDecodeOpEn_RM},    // RCL/2, etc.
    {0xD1, _xDecodeOpEn_RM},    // RCL/2, etc.
    {0xD2, _xDecodeOpEn_RM},    // RCL/2, etc.
    {0xD3, _xDecodeOpEn_RM},    // RCL/2, etc.
#ifdef DETOURS_X64
    {0xD4, _InvalidCopy}, // Invalid
    {0xD5, _InvalidCopy}, // Invalid
#else
    {0xD4, _xDecodeOpEn_I_8},      // AAM
    {0xD5, _xDecodeOpEn_I_8},      // AAD
#endif
    {0xD6, _InvalidCopy},         // Invalid
    {0xD7, _xDecodeOpEn_ZO},          // XLAT/XLATB
    {0xD8, _xDecodeOpEn_RM},      // FADD, etc.
    {0xD9, _xDecodeOpEn_RM},      // F2XM1, etc.
    {0xDA, _xDecodeOpEn_RM},      // FLADD, etc.
    {0xDB, _xDecodeOpEn_RM},      // FCLEX, etc.
    {0xDC, _xDecodeOpEn_RM},      // FADD/0, etc.
    {0xDD, _xDecodeOpEn_RM},      // FFREE, etc.
    {0xDE, _xDecodeOpEn_RM},      // FADDP, etc.
    {0xDF, _xDecodeOpEn_RM},      // FBLD/4, etc.
    {0xE0, _CopyBytes2CantJump},  // LOOPNE cb
    {0xE1, _CopyBytes2CantJump},  // LOOPE cb
    {0xE2, _CopyBytes2CantJump},  // LOOP cb
    {0xE3, _CopyBytes2CantJump},  // JCXZ/JECXZ
    {0xE4, _xDecodeOpEn_I_8},     // IN ib
    {0xE5, _xDecodeOpEn_I_8},     // IN id
    {0xE6, _xDecodeOpEn_I_8},     // OUT ib
    {0xE7, _xDecodeOpEn_I_8},     // OUT ib
    {0xE8, _CopyBytes3Or5Target}, // CALL cd
    {0xE9, _CopyBytes3Or5Target}, // JMP cd
#ifdef DETOURS_X64
    {0xEA, _InvalidCopy}, // Invalid
#else
    {0xEA, _CopyBytes5Or7Dynamic}, // JMP cp
#endif
    {0xEB, _xDecodeOpEn_D},     // JMP cb
    {0xEC, _xDecodeOpEn_ZO},        // IN ib
    {0xED, _xDecodeOpEn_ZO},        // IN id
    {0xEE, _xDecodeOpEn_ZO},        // OUT
    {0xEF, _xDecodeOpEn_ZO},        // OUT
    {0xF0, _CopyBytesPrefix},   // LOCK prefix
    {0xF1, _CopyBytes1Dynamic}, // INT1 / ICEBP somewhat documented by AMD, not by Intel
    {0xF2, _CopyF2},            // REPNE prefix
#ifdef DETOURS_X86
    {0xF3, _CopyF3}, // REPE prefix
#else
                                   // This does presently suffice for AMD64 but it requires tracing
                                   // through a bunch of code to verify and seems not worth maintaining.
    {0xF3, _CopyBytesPrefix},      // REPE prefix
#endif
    {0xF4, _xDecodeOpEn_ZO},     // HLT
    {0xF5, _xDecodeOpEn_ZO},     // CMC
    {0xF6, _CopyF6},         // TEST/0, DIV/6
    {0xF7, _CopyF7},         // TEST/0, DIV/6
    {0xF8, _xDecodeOpEn_ZO},     // CLC
    {0xF9, _xDecodeOpEn_ZO},     // STC
    {0xFA, _xDecodeOpEn_ZO},     // CLI
    {0xFB, _xDecodeOpEn_ZO},     // STI
    {0xFC, _xDecodeOpEn_ZO},     // CLD
    {0xFD, _xDecodeOpEn_ZO},     // STD
    {0xFE, _xDecodeOpEn_RM}, // DEC/1,INC/0
    {0xFF, _CopyFF},         // CALL/2
    {0, _EndCopy},
};

#endif //HOOKZZ_X64IPRELATIVEOPCODETABLE_H
