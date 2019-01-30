#ifndef HOOKZZ_X64IPRELATIVEOPCODETABLE_H
#define HOOKZZ_X64IPRELATIVEOPCODETABLE_H

#ifndef __addr_t_defined
#define __addr_t_defined
typedef char *addr_t;
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

  // OpcodeType OpTy;

  int OpSz;

  struct Instr instr;
};

struct OpcodeDecodeItem {
  unsigned char opcode;
  int FixedSize;
  int OpEn;
  int OpSz;
  // int flag;
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

enum OpcodeFlag { OPCODE, PREFIX };

enum OpSize { OpSz_0 = 0, OpSz_8 = 1, OpSz_16 = 2, OpSz_32 = 4, OpSz_16or32 = OpSz_16 | OpSz_32 , OpSz_64};

enum ImmSize { ImmSz_0 = 0, ImmSz_8 = 8, ImmSz_16 = 16, ImmSz_32 = 32, ImmSz_16or32 = ImmSz_16 | ImmSz_32 , ImmSz64};

#define OpSz_NONE (OpSz_0 | ImmSz_0)

extern OpcodeDecodeItem OpcodeDecodeTable[257];

void _DecodePrefix(InstrMnemonic *instr, addr_t p);

#endif
