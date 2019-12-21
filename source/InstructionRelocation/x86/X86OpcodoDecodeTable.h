#ifndef X86_OPCODE_DECODE_TABLE_H
#define X86_OPCODE_DECODE_TABLE_H

#ifndef __addr_t_defined
#define __addr_t_defined
typedef unsigned long long addr_t;
#endif

#ifndef __byte_defined
#define __byte_defined
typedef unsigned char byte;
#endif

#ifndef __uint_defined
#define __uint_defined
typedef unsigned int uint;
#endif

#ifndef __word_defined
#define __word_defined
typedef short word;
#endif

#ifndef __dword_defined
#define __dword_defined
typedef int dword;
#endif

enum OpcodeType { OpTy_Op1, OpTy_RegInOp1, OpTy_Op1ExtraOp };

struct Instr {
  byte prefix;

  byte REX;

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
      byte Mod : 2;
      byte RegOpcode : 3;
      byte RM : 3;
    };
  };

  union {
    byte SIB;
    struct {
      byte base : 2;
      byte index : 3;
      byte scale : 3;
    };
  };

  byte Displacement[4];
  int DisplacementOffset;

  byte Immediate[4];
  int ImmediateOffset;
};

// clang-format off
enum OperandSize {
  OpSz_0 = 0,
  OpSz_8=1,
  OpSz_16=2,
  OpSz_32=4,
  OpSz_64=8
};

enum ImmediteSize {
  ImmSz_0      = 0,
  ImmSz_8=1,
  ImmSz_16=2,
  ImmSz_32=4,
  ImmSz_64=8
};

enum InstrFlag {
  kNoFlag = 0,
  kIPRelativeAddress = 1
};
// clang-format on

struct InstrMnemonic {
  uint len;

  int flag;

  OperandSize OperandSz;

  ImmediteSize ImmediteSz;

  struct Instr instr;
};

struct OpcodeDecodeItem {
  unsigned char opcode;

  int FixedSize;

  int OpEn;

  int OperandSz;

  int ImmediteSz;

  void (*DecodeHandler)(InstrMnemonic *, addr_t);
};

// clang-format off
enum OperandEncodingType {
  OpEn_NONE =0,
  OpEn_ZO,
  OpEn_M,
  OpEn_I,
  OpEn_D,
  OpEn_O,
  OpEn_RM,
  OpEn_MR,
  OpEn_MI,
  OpEn_OI,
  OpEn_M1,
  OpEn_MC,
  OpEn_RMI
};

// clang-format on

extern OpcodeDecodeItem OpcodeDecodeTable[257];

void _DecodePrefix(InstrMnemonic *instr, addr_t p);

#endif
