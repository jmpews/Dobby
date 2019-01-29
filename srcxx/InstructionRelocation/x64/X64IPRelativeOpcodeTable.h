#ifndef HOOKZZ_X64IPRELATIVEOPCODETABLE_H
#define HOOKZZ_X64IPRELATIVEOPCODETABLE_H

#ifndef __addr_t_defined
#define __addr_t_defined
typedef char *addr_t;
#endif

#ifndef __byte_defined
#define __byte_defined
typedef char byte;
#endif

#ifndef __uint_defined
#define __uint_defined
typedef unsigned int uint;
#endif

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
    struct {
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

struct OpcodeDecodeItem {
  unsigned char opcode;
  uint FixedSize;
  uint OpEn;
  uint OpSz;
  void (*DecodeHandler)(InstrMnemonic *, addr_t);
};

// clang-format off
enum OperandEncodingType {
  OpEn_ZO = 0,
  OpEn_M,
  OpEn_I,
  OpEn_D,
  OpEn_O,
  OpEn_RM,
  OpEn_MR,
  OpEn_MI,
  OpEn_OI,
  OpEn_RMI
};
// clang-format on

enum UnsuppordOperandEncodingType { OpEn_M1, OpEn_MC };

enum OpSize { OpSz_8 = 1, OpSz_16 = 2, OpSz_16or32 = 4 };

enum ImmSize { ImmSz_8 = 8, ImmSz_16 = 16, ImmSz_16or32 = 32 };

extern OpcodeDecodeItem OpcodeDecodeTable[257];

#endif
