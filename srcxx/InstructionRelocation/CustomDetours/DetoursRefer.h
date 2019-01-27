
typedef uword unsigned long;
typedef byte char;

typedef byte *(*DecodeCallbackHandler)(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);

// nFlagBits flags.
enum {
  DYNAMIC   = 0x1u,
  ADDRESS   = 0x2u,
  NOENLARGE = 0x4u,
  RAX       = 0x8u,
};

// ModR/M Flags
enum {
  SIB    = 0x10u,
  RIP    = 0x20u,
  NOTSIB = 0x0fu,
};

enum OperandType {
  UNSET_OP_ORDER = 0, // Operand size decides between 16, 32 and 64 bit operands.
  RegisterOperandCombine,
  OperandRegisterCombine,
  RegisterOnly,
  OperandOnly
};

struct InstrMnemonic {
  uint8_t prefix;
  uint8_t opcode[3];
  uint8_t ModRM;
  uint8_t Displacement[4];
  uint8_t Immediate[4];
};

struct OpcodeItem {
  // Many of these fields are often ignored. See _DataIgnored.
  uword nOpcode : 8;              // Opcode (ignored)
  uword nFixedSize : 4;           // Fixed size of opcode
  uword nFixedSize16 : 4;         // Fixed size when 16 bit operand
  uword nModOffset : 4;           // Offset to mod/rm byte (0=none)
  uword nRelOffset : 4;           // Offset to relative target.
  uword nFlagBits : 4;            // Flags for DYNAMIC, etc.
  DecodeCallbackHandler callback; // Function pointer.
};

struct DecodeOffset {
  uint8_t prefix;
  uint8_t opcode;
  uint8_t ModRM;
  uint8_t disp;
  uint8_t imm;
};

// clang-format off
// These macros define common uses of nFixedSize, nFixedSize16, nModOffset, nRelOffset, nFlagBits, pfCopy.
#define _DataIgnored           0, 0, 0, 0, 0,
#define _CopyBytes1            1, 1, 0, 0, 0, &_xCopyBytes
#ifdef DETOURS_X64
#define _CopyBytes1Address     9, 5, 0, 0, ADDRESS, &_xCopyBytes
#else
#define _CopyBytes1Address     5, 3, 0, 0, ADDRESS, &_xCopyBytes
#endif
#define _CopyBytes1Dynamic     1, 1, 0, 0, DYNAMIC, &_xCopyBytes
#define _CopyBytes2            2, 2, 0, 0, 0, &_xCopyBytes
#define _CopyBytes2Jump        _DataIgnored &_xCopyBytesJump
#define _CopyBytes2CantJump    2, 2, 0, 1, NOENLARGE, &_xCopyBytes
#define _CopyBytes2Dynamic     2, 2, 0, 0, DYNAMIC, &_xCopyBytes
#define _CopyBytes3            3, 3, 0, 0, 0, &_xCopyBytes
#define _CopyBytes3Dynamic     3, 3, 0, 0, DYNAMIC, &_xCopyBytes
#define _CopyBytes3Or5         5, 3, 0, 0, 0, &_xCopyBytes
#define _CopyBytes3Or5Dynamic  5, 3, 0, 0, DYNAMIC, &_xCopyBytes // x86 only
#ifdef DETOURS_X64
#define _CopyBytes3Or5Rax      5, 3, 0, 0, RAX, &_xCopyBytes
#define _CopyBytes3Or5Target   5, 5, 0, 1, 0, &_xCopyBytes
#else
#define _CopyBytes3Or5Rax      5, 3, 0, 0, 0, &_xCopyBytes
#define _CopyBytes3Or5Target   5, 3, 0, 1, 0, &_xCopyBytes
#endif
#define _CopyBytes4            4, 4, 0, 0, 0, &_xCopyBytes
#define _CopyBytes5            5, 5, 0, 0, 0, &_xCopyBytes
#define _CopyBytes5Or7Dynamic  7, 5, 0, 0, DYNAMIC, &_xCopyBytes
#define _CopyBytes7            7, 7, 0, 0, 0, &_xCopyBytes
#define _CopyBytes2Mod         2, 2, 1, 0, 0, &_xCopyBytes
#define _CopyBytes2ModDynamic  2, 2, 1, 0, DYNAMIC, &_xCopyBytes
#define _CopyBytes2Mod1        3, 3, 1, 0, 0, &_xCopyBytes
#define _CopyBytes2ModOperand  6, 4, 1, 0, 0, &_xCopyBytes
#define _CopyBytes3Mod         3, 3, 2, 0, 0, &_xCopyBytes // SSE3 0F 38 opcode modrm
#define _CopyBytes3Mod1        4, 4, 2, 0, 0, &_xCopyBytes // SSE3 0F 3A opcode modrm .. imm8
#define _CopyBytesPrefix       _DataIgnored &_xCopyBytesPrefix
#define _CopyBytesSegment      _DataIgnored &_xCopyBytesSegment
#define _CopyBytesRax          _DataIgnored &_xCopyBytesRax
#define _CopyF2                _DataIgnored &_xCopyF2
#define _CopyF3                _DataIgnored &_xCopyF3   // 32bit x86 only
#define _Copy0F                _DataIgnored &_xCopy0F
#define _Copy0F78              _DataIgnored &_xCopy0F78
#define _Copy0F00              _DataIgnored &_xCopy0F00 // 32bit x86 only
#define _Copy0FB8              _DataIgnored &_xCopy0FB8 // 32bit x86 only
#define _Copy66                _DataIgnored &_xCopy66
#define _Copy67                _DataIgnored &_xCopy67
#define _CopyF6                _DataIgnored &_xCopyF6
#define _CopyF7                _DataIgnored &_xCopyF7
#define _CopyFF                _DataIgnored &_xCopyFF
#define _CopyVex2              _DataIgnored &_xCopyVex2
#define _CopyVex3              _DataIgnored &_xCopyVex3
#define _InvalidCopy               _DataIgnored &_xInvalid
#define _EndCopy                   _DataIgnored NULL

byte *_xCopyBytes(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *_xCopyBytesPrefix(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *_xCopyBytesSegment(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *_xCopyBytesRax(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *_xCopyBytesJump(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);

byte *_xCopy0F(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *_xCopy0F00(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc); // x86 only sldt/0 str/1 lldt/2 ltr/3 err/4 verw/5 jmpe/6/dynamic invalid/7
byte *_xCopy0F78(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc); // vmread, 66/extrq/ib/ib, F2/insertq/ib/ib
byte *_xCopy0FB8(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc); // jmpe or F3/popcnt
byte *_xCopy66(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *_xCopy67(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *_xCopyF2(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *_xCopyF3(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc); // x86 only
byte *_xCopyF6(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *_xCopyF7(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *_xCopyFF(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *_xCopyVex2(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *_xCopyVex3(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);
byte *CopyVexCommon(BYTE m, byte *pbDst, byte *pbSrc);

byte *Invalid(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc);

// clang-format on
byte *_xCopyBytes(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc) {
  UINT nBytesFixed;

  ASSERT(!m_bVex || pEntry->nFlagBits == 0);
  ASSERT(!m_bVex || pEntry->nFixedSize == pEntry->nFixedSize16);

  UINT const nModOffset   = pEntry->nModOffset;
  UINT const nFlagBits    = pEntry->nFlagBits;
  UINT const nFixedSize   = pEntry->nFixedSize;
  UINT const nFixedSize16 = pEntry->nFixedSize16;

  if (nFlagBits & ADDRESS) {
    nBytesFixed = m_bAddressOverride ? nFixedSize16 : nFixedSize;
  }
#ifdef DETOURS_X64
  // REX.W trumps 66
  else if (m_bRaxOverride) {
    nBytesFixed = nFixedSize + ((nFlagBits & RAX) ? 4 : 0);
  }
#endif
  else {
    nBytesFixed = m_bOperandOverride ? nFixedSize16 : nFixedSize;
  }

  UINT nBytes     = nBytesFixed;
  UINT nRelOffset = pEntry->nRelOffset;
  UINT cbTarget   = nBytes - nRelOffset;
  if (nModOffset > 0) {
    ASSERT(nRelOffset == 0);
    BYTE const bModRm = pbSrc[nModOffset];
    BYTE const bFlags = s_rbModRm[bModRm];

    nBytes += bFlags & NOTSIB;
    ., if (bFlags & SIB) {
      BYTE const bSib = pbSrc[nModOffset + 1];

      if ((bSib & 0x07) == 0x05) {
        if ((bModRm & 0xc0) == 0x00) {
          nBytes += 4;
        } else if ((bModRm & 0xc0) == 0x40) {
          nBytes += 1;
        } else if ((bModRm & 0xc0) == 0x80) {
          nBytes += 4;
        }
      }
      cbTarget = nBytes - nRelOffset;
    }
#ifdef DETOURS_X64
    else if (bFlags & RIP) {
      nRelOffset = nModOffset + 1;
      cbTarget   = 4;
    }
#endif
  }
  CopyMemory(pbDst, pbSrc, nBytes);

  if (nRelOffset) {
    *m_ppbTarget = AdjustTarget(pbDst, pbSrc, nBytes, nRelOffset, cbTarget);
#ifdef DETOURS_X64
    if (pEntry->nRelOffset == 0) {
      // This is a data target, not a code target, so we shouldn't return it.
      *m_ppbTarget = NULL;
    }
#endif
  }
  if (nFlagBits & NOENLARGE) {
    *m_plExtra = -*m_plExtra;
  }
  if (nFlagBits & DYNAMIC) {
    *m_ppbTarget = (byte *)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
  }
  return pbSrc + nBytes;
}

byte *_xCopyBytesPrefix(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc) {
  pbDst[0] = pbSrc[0];
  pEntry   = &s_rceCopyTable[pbSrc[1]];
  return (this->*pEntry->pfCopy)(pEntry, pbDst + 1, pbSrc + 1);
}

byte *_xCopyBytesSegment(REFCOPYENTRY, byte *pbDst, byte *pbSrc) {
  m_nSegmentOverride = pbSrc[0];
  return CopyBytesPrefix(0, pbDst, pbSrc);
}

byte *_xCopyBytesRax(REFCOPYENTRY, byte *pbDst, byte *pbSrc) { // AMD64 only
  if (pbSrc[0] & 0x8) {
    m_bRaxOverride = TRUE;
  }
  return CopyBytesPrefix(0, pbDst, pbSrc);
}

byte *_xCopyBytesJump(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc) {
  (void)pEntry;

  PVOID pvSrcAddr     = &pbSrc[1];
  PVOID pvDstAddr     = NULL;
  LONG_PTR nOldOffset = (LONG_PTR) * (signed char *&)pvSrcAddr;
  LONG_PTR nNewOffset = 0;

  *m_ppbTarget = pbSrc + 2 + nOldOffset;

  if (pbSrc[0] == 0xeb) {
    pbDst[0]                      = 0xe9;
    pvDstAddr                     = &pbDst[1];
    nNewOffset                    = nOldOffset - ((pbDst - pbSrc) + 3);
    *(UNALIGNED LONG *&)pvDstAddr = (LONG)nNewOffset;

    *m_plExtra = 3;
    return pbSrc + 2;
  }

  ASSERT(pbSrc[0] >= 0x70 && pbSrc[0] <= 0x7f);

  pbDst[0]                      = 0x0f;
  pbDst[1]                      = 0x80 | (pbSrc[0] & 0xf);
  pvDstAddr                     = &pbDst[2];
  nNewOffset                    = nOldOffset - ((pbDst - pbSrc) + 4);
  *(UNALIGNED LONG *&)pvDstAddr = (LONG)nNewOffset;

  *m_plExtra = 4;
  return pbSrc + 2;
}

byte *_xAdjustTarget(byte *pbDst, byte *pbSrc, UINT cbOp, UINT cbTargetOffset, UINT cbTargetSize) {
  byte *pbTarget = NULL;
#if 1 // fault injection to test test code
#if defined(DETOURS_X64)
  typedef LONGLONG T;
#else
  typedef LONG T;
#endif
  T nOldOffset;
  T nNewOffset;
  PVOID pvTargetAddr = &pbDst[cbTargetOffset];

  switch (cbTargetSize) {
  case 1:
    nOldOffset = *(signed char *&)pvTargetAddr;
    break;
  case 2:
    nOldOffset = *(UNALIGNED SHORT *&)pvTargetAddr;
    break;
  case 4:
    nOldOffset = *(UNALIGNED LONG *&)pvTargetAddr;
    break;
#if defined(DETOURS_X64)
  case 8:
    nOldOffset = *(UNALIGNED LONGLONG *&)pvTargetAddr;
    break;
#endif
  default:
    ASSERT(!"cbTargetSize is invalid.");
    nOldOffset = 0;
    break;
  }

  pbTarget   = pbSrc + cbOp + nOldOffset;
  nNewOffset = nOldOffset - (T)(pbDst - pbSrc);

  switch (cbTargetSize) {
  case 1:
    *(CHAR *&)pvTargetAddr = (CHAR)nNewOffset;
    if (nNewOffset < SCHAR_MIN || nNewOffset > SCHAR_MAX) {
      *m_plExtra = sizeof(uword) - 1;
    }
    break;
  case 2:
    *(UNALIGNED SHORT *&)pvTargetAddr = (SHORT)nNewOffset;
    if (nNewOffset < SHRT_MIN || nNewOffset > SHRT_MAX) {
      *m_plExtra = sizeof(uword) - 2;
    }
    break;
  case 4:
    *(UNALIGNED LONG *&)pvTargetAddr = (LONG)nNewOffset;
    if (nNewOffset < LONG_MIN || nNewOffset > LONG_MAX) {
      *m_plExtra = sizeof(uword) - 4;
    }
    break;
#if defined(DETOURS_X64)
  case 8:
    *(UNALIGNED LONGLONG *&)pvTargetAddr = nNewOffset;
    break;
#endif
  }
#ifdef DETOURS_X64
  // When we are only computing size, source and dest can be
  // far apart, distance not encodable in 32bits. Ok.
  // At least still check the lower 32bits.

  if (pbDst >= m_rbScratchDst && pbDst < (sizeof(m_rbScratchDst) + m_rbScratchDst)) {
    ASSERT((((size_t)pbDst + cbOp + nNewOffset) & 0xFFFFFFFF) == (((size_t)pbTarget) & 0xFFFFFFFF));
  } else
#endif
  {
    ASSERT(pbDst + cbOp + nNewOffset == pbTarget);
  }
#endif
  return pbTarget;
}

byte *_xInvalid(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc) {
  (void)pbDst;
  (void)pEntry;
  ASSERT(!"Invalid Instruction");
  return pbSrc + 1;
}

////////////////////////////////////////////////////// Individual Bytes Codes.
//
byte *_xCopy0F(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc) {
  pbDst[0] = pbSrc[0];
  pEntry   = &s_rceCopyTable0F[pbSrc[1]];
  return (this->*pEntry->pfCopy)(pEntry, pbDst + 1, pbSrc + 1);
}

byte *_xCopy0F78(REFCOPYENTRY, byte *pbDst, byte *pbSrc) {
  // vmread, 66/extrq, F2/insertq

  static const COPYENTRY vmread        = {0x78, _CopyBytes2Mod};
  static const COPYENTRY extrq_insertq = {0x78, _CopyBytes4};

  ASSERT(!(m_bF2 && m_bOperandOverride));

  // For insertq and presumably despite documentation extrq, mode must be 11, not checked.
  // insertq/extrq/78 are followed by two immediate bytes, and given mode == 11, mod/rm byte is always one byte,
  // and the 0x78 makes 4 bytes (not counting the 66/F2/F which are accounted for elsewhere)

  OpcodeItem *const pEntry = ((m_bF2 || m_bOperandOverride) ? &extrq_insertq : &vmread);

  return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

byte *_xCopy0F00(REFCOPYENTRY, byte *pbDst, byte *pbSrc) {
  // jmpe is 32bit x86 only
  // Notice that the sizes are the same either way, but jmpe is marked as "dynamic".

  static const COPYENTRY other = {0xB8, _CopyBytes2Mod}; // sldt/0 str/1 lldt/2 ltr/3 err/4 verw/5 jmpe/6 invalid/7
  static const COPYENTRY jmpe  = {0xB8, _CopyBytes2ModDynamic}; // jmpe/6 x86-on-IA64 syscalls

  OpcodeItem *const pEntry = (((6 << 3) == ((7 << 3) & pbSrc[1])) ? &jmpe : &other);
  return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

byte *_xCopy0FB8(REFCOPYENTRY, byte *pbDst, byte *pbSrc) {
  // jmpe is 32bit x86 only

  static const COPYENTRY popcnt = {0xB8, _CopyBytes2Mod};
  static const COPYENTRY jmpe   = {0xB8, _CopyBytes3Or5Dynamic}; // jmpe x86-on-IA64 syscalls
  OpcodeItem *const pEntry      = m_bF3 ? &popcnt : &jmpe;
  return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

byte *_xCopy66(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc) { // Operand-size override prefix
  m_bOperandOverride = TRUE;
  return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

byte *_xCopy67(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc) { // Address size override prefix
  m_bAddressOverride = TRUE;
  return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

byte *_xCopyF2(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc) {
  m_bF2 = TRUE;
  return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

byte *_xCopyF3(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc) { // x86 only
  m_bF3 = TRUE;
  return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

byte *_xCopyF6(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc) {
  (void)pEntry;

  // TEST BYTE /0
  if (0x00 == (0x38 & pbSrc[1])) { // reg(bits 543) of ModR/M == 0
    static const COPYENTRY ce = {0xf6, _CopyBytes2Mod1};
    return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
  }
  // DIV /6
  // IDIV /7
  // IMUL /5
  // MUL /4
  // NEG /3
  // NOT /2

  static const COPYENTRY ce = {0xf6, _CopyBytes2Mod};
  return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
}

byte *_xCopyF7(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc) {
  (void)pEntry;

  // TEST WORD /0
  if (0x00 == (0x38 & pbSrc[1])) { // reg(bits 543) of ModR/M == 0
    static const COPYENTRY ce = {0xf7, _CopyBytes2ModOperand};
    return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
  }

  // DIV /6
  // IDIV /7
  // IMUL /5
  // MUL /4
  // NEG /3
  // NOT /2
  static const COPYENTRY ce = {0xf7, _CopyBytes2Mod};
  return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
}

byte *_xCopyFF(OpcodeItem *pEntry, byte *pbDst, byte *pbSrc) { // INC /0
  // DEC /1
  // CALL /2
  // CALL /3
  // JMP /4
  // JMP /5
  // PUSH /6
  // invalid/7
  (void)pEntry;

  static const COPYENTRY ce = {0xff, _CopyBytes2Mod};
  byte *pbOut               = (this->*ce.pfCopy)(&ce, pbDst, pbSrc);

  BYTE const b1 = pbSrc[1];

  if (0x15 == b1 || 0x25 == b1) { // CALL [], JMP []
#ifdef DETOURS_X64
    // All segments but FS and GS are equivalent.
    if (m_nSegmentOverride != 0x64 && m_nSegmentOverride != 0x65)
#else
    if (m_nSegmentOverride == 0 || m_nSegmentOverride == 0x2E)
#endif
    {
#ifdef DETOURS_X64
      INT32 offset     = *(UNALIGNED INT32 *)&pbSrc[2];
      byte **ppbTarget = (byte **)(pbSrc + 6 + offset);
#else
      byte **ppbTarget = (byte **)(SIZE_T) * (UNALIGNED uword *)&pbSrc[2];
#endif
      if (s_fLimitReferencesToModule && (ppbTarget < (PVOID)s_pbModuleBeg || ppbTarget >= (PVOID)s_pbModuleEnd)) {

        *m_ppbTarget = (byte *)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
      } else {
        // This can access violate on random bytes. Use DetourSetCodeModule.
        *m_ppbTarget = *ppbTarget;
      }
    } else {
      *m_ppbTarget = (byte *)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
    }
  } else if (0x10 == (0x30 & b1) || // CALL /2 or /3  --> reg(bits 543) of ModR/M == 010 or 011
             0x20 == (0x30 & b1)) { // JMP /4 or /5 --> reg(bits 543) of ModR/M == 100 or 101
    *m_ppbTarget = (byte *)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
  }
  return pbOut;
}

byte *_xCopyVexCommon(BYTE m, byte *pbDst, byte *pbSrc)
// m is first instead of last in the hopes of pbDst/pbSrc being
// passed along efficiently in the registers they were already in.
{
  static const COPYENTRY ceF38   = {0x38, _CopyBytes2Mod};
  static const COPYENTRY ceF3A   = {0x3A, _CopyBytes2Mod1};
  static const COPYENTRY Invalid = {0xC4, _InvalidCopy};

  m_bVex = TRUE;
  OpcodeItem *pEntry;
  switch (m) {
  default:
    pEntry = &Invalid;
    break;
  case 1:
    pEntry = &s_rceCopyTable0F[pbSrc[0]];
    break;
  case 2:
    pEntry = &ceF38;
    break;
  case 3:
    pEntry = &ceF3A;
    break;
  }

  switch (pbSrc[-1] & 3) { // p in last byte
  case 0:
    break;
  case 1:
    m_bOperandOverride = TRUE;
    break;
  case 2:
    m_bF3 = TRUE;
    break;
  case 3:
    m_bF2 = TRUE;
    break;
  }

  return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

byte *_xCopyVex3(REFCOPYENTRY, byte *pbDst, byte *pbSrc)
// 3 byte VEX prefix 0xC4
{
#ifdef DETOURS_X86
  const static COPYENTRY ceLES = {0xC4, _CopyBytes2Mod};
  if ((pbSrc[1] & 0xC0) != 0xC0) {
    OpcodeItem *pEntry = &ceLES;
    return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
  }
#endif
  pbDst[0] = pbSrc[0];
  pbDst[1] = pbSrc[1];
  pbDst[2] = pbSrc[2];
#ifdef DETOURS_X64
  m_bRaxOverride |= !!(pbSrc[2] & 0x80); // w in last byte, see CopyBytesRax
#else
  //
  // TODO
  //
  // Usually the VEX.W bit changes the size of a general purpose register and is ignored for 32bit.
  // Sometimes it is an opcode extension.
  // Look in the Intel manual, in the instruction-by-instruction reference, for ".W1",
  // without nearby wording saying it is ignored for 32bit.
  // For example: "VFMADD132PD/VFMADD213PD/VFMADD231PD Fused Multiply-Add of Packed Double-Precision Floating-Point Values".
  //
  // Then, go through each such case and determine if W0 vs. W1 affect the size of the instruction. Probably not.
  // Look for the same encoding but with "W1" changed to "W0".
  // Here is one such pairing:
  // VFMADD132PD/VFMADD213PD/VFMADD231PD Fused Multiply-Add of Packed Double-Precision Floating-Point Values
  //
  // VEX.DDS.128.66.0F38.W1 98 /r A V/V FMA Multiply packed double-precision floating-point values
  // from xmm0 and xmm2/mem, add to xmm1 and
  // put result in xmm0.
  // VFMADD132PD xmm0, xmm1, xmm2/m128
  //
  // VFMADD132PS/VFMADD213PS/VFMADD231PS Fused Multiply-Add of Packed Single-Precision Floating-Point Values
  // VEX.DDS.128.66.0F38.W0 98 /r A V/V FMA Multiply packed single-precision floating-point values
  // from xmm0 and xmm2/mem, add to xmm1 and put
  // result in xmm0.
  // VFMADD132PS xmm0, xmm1, xmm2/m128
  //
#endif
  return CopyVexCommon(pbSrc[1] & 0x1F, pbDst + 3, pbSrc + 3);
}

byte *_xCopyVex2(REFCOPYENTRY, byte *pbDst, byte *pbSrc)
// 2 byte VEX prefix 0xC5
{
#ifdef DETOURS_X86
  const static COPYENTRY ceLDS = {0xC5, _CopyBytes2Mod};
  if ((pbSrc[1] & 0xC0) != 0xC0) {
    OpcodeItem *pEntry = &ceLDS;
    return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
  }
#endif
  pbDst[0] = pbSrc[0];
  pbDst[1] = pbSrc[1];
  return CopyVexCommon(1, pbDst + 2, pbSrc + 2);
}

// clang-format off
///////////////////////////////////////////////////////// Disassembler Tables.
//
const BYTE _xs_rbModRm[256] = {
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 0x
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 1x
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 2x
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 3x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 4x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 5x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 6x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 7x
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // 8x
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // 9x
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // Ax
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // Bx
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Cx
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Dx
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Ex
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0                  // Fx
};

// clang-format on
const _xCOPYENTRY OpcodeHandlerTable[257] = {
    {0x00, _CopyBytes2Mod}, // ADD /r
    {0x01, _CopyBytes2Mod}, // ADD /r
    {0x02, _CopyBytes2Mod}, // ADD /r
    {0x03, _CopyBytes2Mod}, // ADD /r
    {0x04, _CopyBytes2},    // ADD ib
    {0x05, _CopyBytes3Or5}, // ADD iw
#ifdef DETOURS_X64
    {0x06, _InvalidCopy}, // Invalid
    {0x07, _InvalidCopy}, // Invalid
#else
    {0x06, _CopyBytes1},           // PUSH
    {0x07, _CopyBytes1},           // POP
#endif
    {0x08, _CopyBytes2Mod}, // OR /r
    {0x09, _CopyBytes2Mod}, // OR /r
    {0x0A, _CopyBytes2Mod}, // OR /r
    {0x0B, _CopyBytes2Mod}, // OR /r
    {0x0C, _CopyBytes2},    // OR ib
    {0x0D, _CopyBytes3Or5}, // OR iw
#ifdef DETOURS_X64
    {0x0E, _InvalidCopy}, // Invalid
#else
    {0x0E, _CopyBytes1},           // PUSH
#endif
    {0x0F, _Copy0F},        // Extension Ops
    {0x10, _CopyBytes2Mod}, // ADC /r
    {0x11, _CopyBytes2Mod}, // ADC /r
    {0x12, _CopyBytes2Mod}, // ADC /r
    {0x13, _CopyBytes2Mod}, // ADC /r
    {0x14, _CopyBytes2},    // ADC ib
    {0x15, _CopyBytes3Or5}, // ADC id
#ifdef DETOURS_X64
    {0x16, _InvalidCopy}, // Invalid
    {0x17, _InvalidCopy}, // Invalid
#else
    {0x16, _CopyBytes1},           // PUSH
    {0x17, _CopyBytes1},           // POP
#endif
    {0x18, _CopyBytes2Mod}, // SBB /r
    {0x19, _CopyBytes2Mod}, // SBB /r
    {0x1A, _CopyBytes2Mod}, // SBB /r
    {0x1B, _CopyBytes2Mod}, // SBB /r
    {0x1C, _CopyBytes2},    // SBB ib
    {0x1D, _CopyBytes3Or5}, // SBB id
#ifdef DETOURS_X64
    {0x1E, _InvalidCopy}, // Invalid
    {0x1F, _InvalidCopy}, // Invalid
#else
    {0x1E, _CopyBytes1},           // PUSH
    {0x1F, _CopyBytes1},           // POP
#endif
    {0x20, _CopyBytes2Mod},    // AND /r
    {0x21, _CopyBytes2Mod},    // AND /r
    {0x22, _CopyBytes2Mod},    // AND /r
    {0x23, _CopyBytes2Mod},    // AND /r
    {0x24, _CopyBytes2},       // AND ib
    {0x25, _CopyBytes3Or5},    // AND id
    {0x26, _CopyBytesSegment}, // ES prefix
#ifdef DETOURS_X64
    {0x27, _InvalidCopy}, // Invalid
#else
    {0x27, _CopyBytes1},           // DAA
#endif
    {0x28, _CopyBytes2Mod},    // SUB /r
    {0x29, _CopyBytes2Mod},    // SUB /r
    {0x2A, _CopyBytes2Mod},    // SUB /r
    {0x2B, _CopyBytes2Mod},    // SUB /r
    {0x2C, _CopyBytes2},       // SUB ib
    {0x2D, _CopyBytes3Or5},    // SUB id
    {0x2E, _CopyBytesSegment}, // CS prefix
#ifdef DETOURS_X64
    {0x2F, _InvalidCopy}, // Invalid
#else
    {0x2F, _CopyBytes1},           // DAS
#endif
    {0x30, _CopyBytes2Mod},    // XOR /r
    {0x31, _CopyBytes2Mod},    // XOR /r
    {0x32, _CopyBytes2Mod},    // XOR /r
    {0x33, _CopyBytes2Mod},    // XOR /r
    {0x34, _CopyBytes2},       // XOR ib
    {0x35, _CopyBytes3Or5},    // XOR id
    {0x36, _CopyBytesSegment}, // SS prefix
#ifdef DETOURS_X64
    {0x37, _InvalidCopy}, // Invalid
#else
    {0x37, _CopyBytes1},           // AAA
#endif
    {0x38, _CopyBytes2Mod},    // CMP /r
    {0x39, _CopyBytes2Mod},    // CMP /r
    {0x3A, _CopyBytes2Mod},    // CMP /r
    {0x3B, _CopyBytes2Mod},    // CMP /r
    {0x3C, _CopyBytes2},       // CMP ib
    {0x3D, _CopyBytes3Or5},    // CMP id
    {0x3E, _CopyBytesSegment}, // DS prefix
#ifdef DETOURS_X64
    {0x3F, _InvalidCopy}, // Invalid
#else
    {0x3F, _CopyBytes1},           // AAS
#endif
#ifdef DETOURS_X64         // For Rax Prefix
    {0x40, _CopyBytesRax}, // Rax
    {0x41, _CopyBytesRax}, // Rax
    {0x42, _CopyBytesRax}, // Rax
    {0x43, _CopyBytesRax}, // Rax
    {0x44, _CopyBytesRax}, // Rax
    {0x45, _CopyBytesRax}, // Rax
    {0x46, _CopyBytesRax}, // Rax
    {0x47, _CopyBytesRax}, // Rax
    {0x48, _CopyBytesRax}, // Rax
    {0x49, _CopyBytesRax}, // Rax
    {0x4A, _CopyBytesRax}, // Rax
    {0x4B, _CopyBytesRax}, // Rax
    {0x4C, _CopyBytesRax}, // Rax
    {0x4D, _CopyBytesRax}, // Rax
    {0x4E, _CopyBytesRax}, // Rax
    {0x4F, _CopyBytesRax}, // Rax
#else
    {0x40, _CopyBytes1},           // INC
    {0x41, _CopyBytes1},           // INC
    {0x42, _CopyBytes1},           // INC
    {0x43, _CopyBytes1},           // INC
    {0x44, _CopyBytes1},           // INC
    {0x45, _CopyBytes1},           // INC
    {0x46, _CopyBytes1},           // INC
    {0x47, _CopyBytes1},           // INC
    {0x48, _CopyBytes1},           // DEC
    {0x49, _CopyBytes1},           // DEC
    {0x4A, _CopyBytes1},           // DEC
    {0x4B, _CopyBytes1},           // DEC
    {0x4C, _CopyBytes1},           // DEC
    {0x4D, _CopyBytes1},           // DEC
    {0x4E, _CopyBytes1},           // DEC
    {0x4F, _CopyBytes1},           // DEC
#endif
    {0x50, _CopyBytes1}, // PUSH
    {0x51, _CopyBytes1}, // PUSH
    {0x52, _CopyBytes1}, // PUSH
    {0x53, _CopyBytes1}, // PUSH
    {0x54, _CopyBytes1}, // PUSH
    {0x55, _CopyBytes1}, // PUSH
    {0x56, _CopyBytes1}, // PUSH
    {0x57, _CopyBytes1}, // PUSH
    {0x58, _CopyBytes1}, // POP
    {0x59, _CopyBytes1}, // POP
    {0x5A, _CopyBytes1}, // POP
    {0x5B, _CopyBytes1}, // POP
    {0x5C, _CopyBytes1}, // POP
    {0x5D, _CopyBytes1}, // POP
    {0x5E, _CopyBytes1}, // POP
    {0x5F, _CopyBytes1}, // POP
#ifdef DETOURS_X64
    {0x60, _InvalidCopy}, // Invalid
    {0x61, _InvalidCopy}, // Invalid
    {0x62, _InvalidCopy}, // Invalid (not yet implemented Intel EVEX support)
#else
    {0x60, _CopyBytes1},           // PUSHAD
    {0x61, _CopyBytes1},           // POPAD
    {0x62, _CopyBytes2Mod},        // BOUND /r
#endif
    {0x63, _CopyBytes2Mod},        // 32bit ARPL /r, 64bit MOVSXD
    {0x64, _CopyBytesSegment},     // FS prefix
    {0x65, _CopyBytesSegment},     // GS prefix
    {0x66, _Copy66},               // Operand Prefix
    {0x67, _Copy67},               // Address Prefix
    {0x68, _CopyBytes3Or5},        // PUSH
    {0x69, _CopyBytes2ModOperand}, // IMUL /r iz
    {0x6A, _CopyBytes2},           // PUSH
    {0x6B, _CopyBytes2Mod1},       // IMUL /r ib
    {0x6C, _CopyBytes1},           // INS
    {0x6D, _CopyBytes1},           // INS
    {0x6E, _CopyBytes1},           // OUTS/OUTSB
    {0x6F, _CopyBytes1},           // OUTS/OUTSW
    {0x70, _CopyBytes2Jump},       // JO           // 0f80
    {0x71, _CopyBytes2Jump},       // JNO          // 0f81
    {0x72, _CopyBytes2Jump},       // JB/JC/JNAE   // 0f82
    {0x73, _CopyBytes2Jump},       // JAE/JNB/JNC  // 0f83
    {0x74, _CopyBytes2Jump},       // JE/JZ        // 0f84
    {0x75, _CopyBytes2Jump},       // JNE/JNZ      // 0f85
    {0x76, _CopyBytes2Jump},       // JBE/JNA      // 0f86
    {0x77, _CopyBytes2Jump},       // JA/JNBE      // 0f87
    {0x78, _CopyBytes2Jump},       // JS           // 0f88
    {0x79, _CopyBytes2Jump},       // JNS          // 0f89
    {0x7A, _CopyBytes2Jump},       // JP/JPE       // 0f8a
    {0x7B, _CopyBytes2Jump},       // JNP/JPO      // 0f8b
    {0x7C, _CopyBytes2Jump},       // JL/JNGE      // 0f8c
    {0x7D, _CopyBytes2Jump},       // JGE/JNL      // 0f8d
    {0x7E, _CopyBytes2Jump},       // JLE/JNG      // 0f8e
    {0x7F, _CopyBytes2Jump},       // JG/JNLE      // 0f8f
    {0x80, _CopyBytes2Mod1},       // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 byte reg, immediate byte
    {0x81, _CopyBytes2ModOperand}, // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 byte reg, immediate word or dword
#ifdef DETOURS_X64
    {0x82, _InvalidCopy}, // Invalid
#else
    {0x82, _CopyBytes2Mod1},       // MOV al,x
#endif
    {0x83, _CopyBytes2Mod1}, // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 reg, immediate byte
    {0x84, _CopyBytes2Mod},  // TEST /r
    {0x85, _CopyBytes2Mod},  // TEST /r
    {0x86, _CopyBytes2Mod},  // XCHG /r @todo
    {0x87, _CopyBytes2Mod},  // XCHG /r @todo
    {0x88, _CopyBytes2Mod},  // MOV /r
    {0x89, _CopyBytes2Mod},  // MOV /r
    {0x8A, _CopyBytes2Mod},  // MOV /r
    {0x8B, _CopyBytes2Mod},  // MOV /r
    {0x8C, _CopyBytes2Mod},  // MOV /r
    {0x8D, _CopyBytes2Mod},  // LEA /r
    {0x8E, _CopyBytes2Mod},  // MOV /r
    {0x8F, _CopyBytes2Mod},  // POP /0
    {0x90, _CopyBytes1},     // NOP
    {0x91, _CopyBytes1},     // XCHG
    {0x92, _CopyBytes1},     // XCHG
    {0x93, _CopyBytes1},     // XCHG
    {0x94, _CopyBytes1},     // XCHG
    {0x95, _CopyBytes1},     // XCHG
    {0x96, _CopyBytes1},     // XCHG
    {0x97, _CopyBytes1},     // XCHG
    {0x98, _CopyBytes1},     // CWDE
    {0x99, _CopyBytes1},     // CDQ
#ifdef DETOURS_X64
    {0x9A, _InvalidCopy}, // Invalid
#else
    {0x9A, _CopyBytes5Or7Dynamic}, // CALL cp
#endif
    {0x9B, _CopyBytes1},           // WAIT/FWAIT
    {0x9C, _CopyBytes1},           // PUSHFD
    {0x9D, _CopyBytes1},           // POPFD
    {0x9E, _CopyBytes1},           // SAHF
    {0x9F, _CopyBytes1},           // LAHF
    {0xA0, _CopyBytes1Address},    // MOV
    {0xA1, _CopyBytes1Address},    // MOV
    {0xA2, _CopyBytes1Address},    // MOV
    {0xA3, _CopyBytes1Address},    // MOV
    {0xA4, _CopyBytes1},           // MOVS
    {0xA5, _CopyBytes1},           // MOVS/MOVSD
    {0xA6, _CopyBytes1},           // CMPS/CMPSB
    {0xA7, _CopyBytes1},           // CMPS/CMPSW
    {0xA8, _CopyBytes2},           // TEST
    {0xA9, _CopyBytes3Or5},        // TEST
    {0xAA, _CopyBytes1},           // STOS/STOSB
    {0xAB, _CopyBytes1},           // STOS/STOSW
    {0xAC, _CopyBytes1},           // LODS/LODSB
    {0xAD, _CopyBytes1},           // LODS/LODSW
    {0xAE, _CopyBytes1},           // SCAS/SCASB
    {0xAF, _CopyBytes1},           // SCAS/SCASD
    {0xB0, _CopyBytes2},           // MOV B0+rb
    {0xB1, _CopyBytes2},           // MOV B0+rb
    {0xB2, _CopyBytes2},           // MOV B0+rb
    {0xB3, _CopyBytes2},           // MOV B0+rb
    {0xB4, _CopyBytes2},           // MOV B0+rb
    {0xB5, _CopyBytes2},           // MOV B0+rb
    {0xB6, _CopyBytes2},           // MOV B0+rb
    {0xB7, _CopyBytes2},           // MOV B0+rb
    {0xB8, _CopyBytes3Or5Rax},     // MOV B8+rb
    {0xB9, _CopyBytes3Or5Rax},     // MOV B8+rb
    {0xBA, _CopyBytes3Or5Rax},     // MOV B8+rb
    {0xBB, _CopyBytes3Or5Rax},     // MOV B8+rb
    {0xBC, _CopyBytes3Or5Rax},     // MOV B8+rb
    {0xBD, _CopyBytes3Or5Rax},     // MOV B8+rb
    {0xBE, _CopyBytes3Or5Rax},     // MOV B8+rb
    {0xBF, _CopyBytes3Or5Rax},     // MOV B8+rb
    {0xC0, _CopyBytes2Mod1},       // RCL/2 ib, etc.
    {0xC1, _CopyBytes2Mod1},       // RCL/2 ib, etc.
    {0xC2, _CopyBytes3},           // RET
    {0xC3, _CopyBytes1},           // RET
    {0xC4, _CopyVex3},             // LES, VEX 3-byte opcodes.
    {0xC5, _CopyVex2},             // LDS, VEX 2-byte opcodes.
    {0xC6, _CopyBytes2Mod1},       // MOV
    {0xC7, _CopyBytes2ModOperand}, // MOV/0 XBEGIN/7
    {0xC8, _CopyBytes4},           // ENTER
    {0xC9, _CopyBytes1},           // LEAVE
    {0xCA, _CopyBytes3Dynamic},    // RET
    {0xCB, _CopyBytes1Dynamic},    // RET
    {0xCC, _CopyBytes1Dynamic},    // INT 3
    {0xCD, _CopyBytes2Dynamic},    // INT ib
#ifdef DETOURS_X64
    {0xCE, _InvalidCopy}, // Invalid
#else
    {0xCE, _CopyBytes1Dynamic},    // INTO
#endif
    {0xCF, _CopyBytes1Dynamic}, // IRET
    {0xD0, _CopyBytes2Mod},     // RCL/2, etc.
    {0xD1, _CopyBytes2Mod},     // RCL/2, etc.
    {0xD2, _CopyBytes2Mod},     // RCL/2, etc.
    {0xD3, _CopyBytes2Mod},     // RCL/2, etc.
#ifdef DETOURS_X64
    {0xD4, _InvalidCopy}, // Invalid
    {0xD5, _InvalidCopy}, // Invalid
#else
    {0xD4, _CopyBytes2},           // AAM
    {0xD5, _CopyBytes2},           // AAD
#endif
    {0xD6, _InvalidCopy},         // Invalid
    {0xD7, _CopyBytes1},          // XLAT/XLATB
    {0xD8, _CopyBytes2Mod},       // FADD, etc.
    {0xD9, _CopyBytes2Mod},       // F2XM1, etc.
    {0xDA, _CopyBytes2Mod},       // FLADD, etc.
    {0xDB, _CopyBytes2Mod},       // FCLEX, etc.
    {0xDC, _CopyBytes2Mod},       // FADD/0, etc.
    {0xDD, _CopyBytes2Mod},       // FFREE, etc.
    {0xDE, _CopyBytes2Mod},       // FADDP, etc.
    {0xDF, _CopyBytes2Mod},       // FBLD/4, etc.
    {0xE0, _CopyBytes2CantJump},  // LOOPNE cb
    {0xE1, _CopyBytes2CantJump},  // LOOPE cb
    {0xE2, _CopyBytes2CantJump},  // LOOP cb
    {0xE3, _CopyBytes2CantJump},  // JCXZ/JECXZ
    {0xE4, _CopyBytes2},          // IN ib
    {0xE5, _CopyBytes2},          // IN id
    {0xE6, _CopyBytes2},          // OUT ib
    {0xE7, _CopyBytes2},          // OUT ib
    {0xE8, _CopyBytes3Or5Target}, // CALL cd
    {0xE9, _CopyBytes3Or5Target}, // JMP cd
#ifdef DETOURS_X64
    {0xEA, _InvalidCopy}, // Invalid
#else
    {0xEA, _CopyBytes5Or7Dynamic}, // JMP cp
#endif
    {0xEB, _CopyBytes2Jump},    // JMP cb
    {0xEC, _CopyBytes1},        // IN ib
    {0xED, _CopyBytes1},        // IN id
    {0xEE, _CopyBytes1},        // OUT
    {0xEF, _CopyBytes1},        // OUT
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
    {0xF4, _CopyBytes1},    // HLT
    {0xF5, _CopyBytes1},    // CMC
    {0xF6, _CopyF6},        // TEST/0, DIV/6
    {0xF7, _CopyF7},        // TEST/0, DIV/6
    {0xF8, _CopyBytes1},    // CLC
    {0xF9, _CopyBytes1},    // STC
    {0xFA, _CopyBytes1},    // CLI
    {0xFB, _CopyBytes1},    // STI
    {0xFC, _CopyBytes1},    // CLD
    {0xFD, _CopyBytes1},    // STD
    {0xFE, _CopyBytes2Mod}, // DEC/1,INC/0
    {0xFF, _CopyFF},        // CALL/2
    {0, _EndCopy},
};

const _xCOPYENTRY _xs_rceCopyTable0F[257] = {
#ifdef DETOURS_X86
    {0x00, _Copy0F00}, // sldt/0 str/1 lldt/2 ltr/3 err/4 verw/5 jmpe/6/dynamic invalid/7
#else
    {0x00, _CopyBytes2Mod},        // sldt/0 str/1 lldt/2 ltr/3 err/4 verw/5 jmpe/6/dynamic invalid/7
#endif
    {0x01, _CopyBytes2Mod},  // INVLPG/7, etc.
    {0x02, _CopyBytes2Mod},  // LAR/r
    {0x03, _CopyBytes2Mod},  // LSL/r
    {0x04, _InvalidCopy},    // _04
    {0x05, _CopyBytes1},     // SYSCALL
    {0x06, _CopyBytes1},     // CLTS
    {0x07, _CopyBytes1},     // SYSRET
    {0x08, _CopyBytes1},     // INVD
    {0x09, _CopyBytes1},     // WBINVD
    {0x0A, _InvalidCopy},    // _0A
    {0x0B, _CopyBytes1},     // UD2
    {0x0C, _InvalidCopy},    // _0C
    {0x0D, _CopyBytes2Mod},  // PREFETCH
    {0x0E, _CopyBytes1},     // FEMMS (3DNow -- not in Intel documentation)
    {0x0F, _CopyBytes2Mod1}, // 3DNow Opcodes
    {0x10, _CopyBytes2Mod},  // MOVSS MOVUPD MOVSD
    {0x11, _CopyBytes2Mod},  // MOVSS MOVUPD MOVSD
    {0x12, _CopyBytes2Mod},  // MOVLPD
    {0x13, _CopyBytes2Mod},  // MOVLPD
    {0x14, _CopyBytes2Mod},  // UNPCKLPD
    {0x15, _CopyBytes2Mod},  // UNPCKHPD
    {0x16, _CopyBytes2Mod},  // MOVHPD
    {0x17, _CopyBytes2Mod},  // MOVHPD
    {0x18, _CopyBytes2Mod},  // PREFETCHINTA...
    {0x19, _CopyBytes2Mod},  // NOP/r multi byte nop, not documented by Intel, documented by AMD
    {0x1A, _CopyBytes2Mod},  // NOP/r multi byte nop, not documented by Intel, documented by AMD
    {0x1B, _CopyBytes2Mod},  // NOP/r multi byte nop, not documented by Intel, documented by AMD
    {0x1C, _CopyBytes2Mod},  // NOP/r multi byte nop, not documented by Intel, documented by AMD
    {0x1D, _CopyBytes2Mod},  // NOP/r multi byte nop, not documented by Intel, documented by AMD
    {0x1E, _CopyBytes2Mod},  // NOP/r multi byte nop, not documented by Intel, documented by AMD
    {0x1F, _CopyBytes2Mod},  // NOP/r multi byte nop
    {0x20, _CopyBytes2Mod},  // MOV/r
    {0x21, _CopyBytes2Mod},  // MOV/r
    {0x22, _CopyBytes2Mod},  // MOV/r
    {0x23, _CopyBytes2Mod},  // MOV/r
#ifdef DETOURS_X64
    {0x24, _InvalidCopy}, // _24
#else
    {0x24, _CopyBytes2Mod},        // MOV/r,TR TR is test register on 80386 and 80486, removed in Pentium
#endif
    {0x25, _InvalidCopy}, // _25
#ifdef DETOURS_X64
    {0x26, _InvalidCopy}, // _26
#else
    {0x26, _CopyBytes2Mod},        // MOV TR/r TR is test register on 80386 and 80486, removed in Pentium
#endif
    {0x27, _InvalidCopy},    // _27
    {0x28, _CopyBytes2Mod},  // MOVAPS MOVAPD
    {0x29, _CopyBytes2Mod},  // MOVAPS MOVAPD
    {0x2A, _CopyBytes2Mod},  // CVPI2PS &
    {0x2B, _CopyBytes2Mod},  // MOVNTPS MOVNTPD
    {0x2C, _CopyBytes2Mod},  // CVTTPS2PI &
    {0x2D, _CopyBytes2Mod},  // CVTPS2PI &
    {0x2E, _CopyBytes2Mod},  // UCOMISS UCOMISD
    {0x2F, _CopyBytes2Mod},  // COMISS COMISD
    {0x30, _CopyBytes1},     // WRMSR
    {0x31, _CopyBytes1},     // RDTSC
    {0x32, _CopyBytes1},     // RDMSR
    {0x33, _CopyBytes1},     // RDPMC
    {0x34, _CopyBytes1},     // SYSENTER
    {0x35, _CopyBytes1},     // SYSEXIT
    {0x36, _InvalidCopy},    // _36
    {0x37, _CopyBytes1},     // GETSEC
    {0x38, _CopyBytes3Mod},  // SSE3 Opcodes
    {0x39, _InvalidCopy},    // _39
    {0x3A, _CopyBytes3Mod1}, // SSE3 Opcodes
    {0x3B, _InvalidCopy},    // _3B
    {0x3C, _InvalidCopy},    // _3C
    {0x3D, _InvalidCopy},    // _3D
    {0x3E, _InvalidCopy},    // _3E
    {0x3F, _InvalidCopy},    // _3F
    {0x40, _CopyBytes2Mod},  // CMOVO (0F 40)
    {0x41, _CopyBytes2Mod},  // CMOVNO (0F 41)
    {0x42, _CopyBytes2Mod},  // CMOVB & CMOVNE (0F 42)
    {0x43, _CopyBytes2Mod},  // CMOVAE & CMOVNB (0F 43)
    {0x44, _CopyBytes2Mod},  // CMOVE & CMOVZ (0F 44)
    {0x45, _CopyBytes2Mod},  // CMOVNE & CMOVNZ (0F 45)
    {0x46, _CopyBytes2Mod},  // CMOVBE & CMOVNA (0F 46)
    {0x47, _CopyBytes2Mod},  // CMOVA & CMOVNBE (0F 47)
    {0x48, _CopyBytes2Mod},  // CMOVS (0F 48)
    {0x49, _CopyBytes2Mod},  // CMOVNS (0F 49)
    {0x4A, _CopyBytes2Mod},  // CMOVP & CMOVPE (0F 4A)
    {0x4B, _CopyBytes2Mod},  // CMOVNP & CMOVPO (0F 4B)
    {0x4C, _CopyBytes2Mod},  // CMOVL & CMOVNGE (0F 4C)
    {0x4D, _CopyBytes2Mod},  // CMOVGE & CMOVNL (0F 4D)
    {0x4E, _CopyBytes2Mod},  // CMOVLE & CMOVNG (0F 4E)
    {0x4F, _CopyBytes2Mod},  // CMOVG & CMOVNLE (0F 4F)
    {0x50, _CopyBytes2Mod},  // MOVMSKPD MOVMSKPD
    {0x51, _CopyBytes2Mod},  // SQRTPS &
    {0x52, _CopyBytes2Mod},  // RSQRTTS RSQRTPS
    {0x53, _CopyBytes2Mod},  // RCPPS RCPSS
    {0x54, _CopyBytes2Mod},  // ANDPS ANDPD
    {0x55, _CopyBytes2Mod},  // ANDNPS ANDNPD
    {0x56, _CopyBytes2Mod},  // ORPS ORPD
    {0x57, _CopyBytes2Mod},  // XORPS XORPD
    {0x58, _CopyBytes2Mod},  // ADDPS &
    {0x59, _CopyBytes2Mod},  // MULPS &
    {0x5A, _CopyBytes2Mod},  // CVTPS2PD &
    {0x5B, _CopyBytes2Mod},  // CVTDQ2PS &
    {0x5C, _CopyBytes2Mod},  // SUBPS &
    {0x5D, _CopyBytes2Mod},  // MINPS &
    {0x5E, _CopyBytes2Mod},  // DIVPS &
    {0x5F, _CopyBytes2Mod},  // MASPS &
    {0x60, _CopyBytes2Mod},  // PUNPCKLBW/r
    {0x61, _CopyBytes2Mod},  // PUNPCKLWD/r
    {0x62, _CopyBytes2Mod},  // PUNPCKLWD/r
    {0x63, _CopyBytes2Mod},  // PACKSSWB/r
    {0x64, _CopyBytes2Mod},  // PCMPGTB/r
    {0x65, _CopyBytes2Mod},  // PCMPGTW/r
    {0x66, _CopyBytes2Mod},  // PCMPGTD/r
    {0x67, _CopyBytes2Mod},  // PACKUSWB/r
    {0x68, _CopyBytes2Mod},  // PUNPCKHBW/r
    {0x69, _CopyBytes2Mod},  // PUNPCKHWD/r
    {0x6A, _CopyBytes2Mod},  // PUNPCKHDQ/r
    {0x6B, _CopyBytes2Mod},  // PACKSSDW/r
    {0x6C, _CopyBytes2Mod},  // PUNPCKLQDQ
    {0x6D, _CopyBytes2Mod},  // PUNPCKHQDQ
    {0x6E, _CopyBytes2Mod},  // MOVD/r
    {0x6F, _CopyBytes2Mod},  // MOV/r
    {0x70, _CopyBytes2Mod1}, // PSHUFW/r ib
    {0x71, _CopyBytes2Mod1}, // PSLLW/6 ib,PSRAW/4 ib,PSRLW/2 ib
    {0x72, _CopyBytes2Mod1}, // PSLLD/6 ib,PSRAD/4 ib,PSRLD/2 ib
    {0x73, _CopyBytes2Mod1}, // PSLLQ/6 ib,PSRLQ/2 ib
    {0x74, _CopyBytes2Mod},  // PCMPEQB/r
    {0x75, _CopyBytes2Mod},  // PCMPEQW/r
    {0x76, _CopyBytes2Mod},  // PCMPEQD/r
    {0x77, _CopyBytes1},     // EMMS
    // extrq/insertq require mode=3 and are followed by two immediate bytes
    {0x78, _Copy0F78}, // VMREAD/r, 66/EXTRQ/r/ib/ib, F2/INSERTQ/r/ib/ib
    // extrq/insertq require mod=3, therefore _CopyBytes2, but it ends up the same
    {0x79, _CopyBytes2Mod},       // VMWRITE/r, 66/EXTRQ/r, F2/INSERTQ/r
    {0x7A, _InvalidCopy},         // _7A
    {0x7B, _InvalidCopy},         // _7B
    {0x7C, _CopyBytes2Mod},       // HADDPS
    {0x7D, _CopyBytes2Mod},       // HSUBPS
    {0x7E, _CopyBytes2Mod},       // MOVD/r
    {0x7F, _CopyBytes2Mod},       // MOV/r
    {0x80, _CopyBytes3Or5Target}, // JO
    {0x81, _CopyBytes3Or5Target}, // JNO
    {0x82, _CopyBytes3Or5Target}, // JB,JC,JNAE
    {0x83, _CopyBytes3Or5Target}, // JAE,JNB,JNC
    {0x84, _CopyBytes3Or5Target}, // JE,JZ,JZ
    {0x85, _CopyBytes3Or5Target}, // JNE,JNZ
    {0x86, _CopyBytes3Or5Target}, // JBE,JNA
    {0x87, _CopyBytes3Or5Target}, // JA,JNBE
    {0x88, _CopyBytes3Or5Target}, // JS
    {0x89, _CopyBytes3Or5Target}, // JNS
    {0x8A, _CopyBytes3Or5Target}, // JP,JPE
    {0x8B, _CopyBytes3Or5Target}, // JNP,JPO
    {0x8C, _CopyBytes3Or5Target}, // JL,NGE
    {0x8D, _CopyBytes3Or5Target}, // JGE,JNL
    {0x8E, _CopyBytes3Or5Target}, // JLE,JNG
    {0x8F, _CopyBytes3Or5Target}, // JG,JNLE
    {0x90, _CopyBytes2Mod},       // CMOVO (0F 40)
    {0x91, _CopyBytes2Mod},       // CMOVNO (0F 41)
    {0x92, _CopyBytes2Mod},       // CMOVB & CMOVC & CMOVNAE (0F 42)
    {0x93, _CopyBytes2Mod},       // CMOVAE & CMOVNB & CMOVNC (0F 43)
    {0x94, _CopyBytes2Mod},       // CMOVE & CMOVZ (0F 44)
    {0x95, _CopyBytes2Mod},       // CMOVNE & CMOVNZ (0F 45)
    {0x96, _CopyBytes2Mod},       // CMOVBE & CMOVNA (0F 46)
    {0x97, _CopyBytes2Mod},       // CMOVA & CMOVNBE (0F 47)
    {0x98, _CopyBytes2Mod},       // CMOVS (0F 48)
    {0x99, _CopyBytes2Mod},       // CMOVNS (0F 49)
    {0x9A, _CopyBytes2Mod},       // CMOVP & CMOVPE (0F 4A)
    {0x9B, _CopyBytes2Mod},       // CMOVNP & CMOVPO (0F 4B)
    {0x9C, _CopyBytes2Mod},       // CMOVL & CMOVNGE (0F 4C)
    {0x9D, _CopyBytes2Mod},       // CMOVGE & CMOVNL (0F 4D)
    {0x9E, _CopyBytes2Mod},       // CMOVLE & CMOVNG (0F 4E)
    {0x9F, _CopyBytes2Mod},       // CMOVG & CMOVNLE (0F 4F)
    {0xA0, _CopyBytes1},          // PUSH
    {0xA1, _CopyBytes1},          // POP
    {0xA2, _CopyBytes1},          // CPUID
    {0xA3, _CopyBytes2Mod},       // BT  (0F A3)
    {0xA4, _CopyBytes2Mod1},      // SHLD
    {0xA5, _CopyBytes2Mod},       // SHLD
    {0xA6, _CopyBytes2Mod},       // XBTS
    {0xA7, _CopyBytes2Mod},       // IBTS
    {0xA8, _CopyBytes1},          // PUSH
    {0xA9, _CopyBytes1},          // POP
    {0xAA, _CopyBytes1},          // RSM
    {0xAB, _CopyBytes2Mod},       // BTS (0F AB)
    {0xAC, _CopyBytes2Mod1},      // SHRD
    {0xAD, _CopyBytes2Mod},       // SHRD

    // 0F AE mod76=mem mod543=0 fxsave
    // 0F AE mod76=mem mod543=1 fxrstor
    // 0F AE mod76=mem mod543=2 ldmxcsr
    // 0F AE mod76=mem mod543=3 stmxcsr
    // 0F AE mod76=mem mod543=4 xsave
    // 0F AE mod76=mem mod543=5 xrstor
    // 0F AE mod76=mem mod543=6 saveopt
    // 0F AE mod76=mem mod543=7 clflush
    // 0F AE mod76=11b mod543=5 lfence
    // 0F AE mod76=11b mod543=6 mfence
    // 0F AE mod76=11b mod543=7 sfence
    // F3 0F AE mod76=11b mod543=0 rdfsbase
    // F3 0F AE mod76=11b mod543=1 rdgsbase
    // F3 0F AE mod76=11b mod543=2 wrfsbase
    // F3 0F AE mod76=11b mod543=3 wrgsbase
    {0xAE,
     _CopyBytes2Mod}, // fxsave fxrstor ldmxcsr stmxcsr xsave xrstor saveopt clflush lfence mfence sfence rdfsbase rdgsbase wrfsbase wrgsbase
    {0xAF, _CopyBytes2Mod}, // IMUL (0F AF)
    {0xB0, _CopyBytes2Mod}, // CMPXCHG (0F B0)
    {0xB1, _CopyBytes2Mod}, // CMPXCHG (0F B1)
    {0xB2, _CopyBytes2Mod}, // LSS/r
    {0xB3, _CopyBytes2Mod}, // BTR (0F B3)
    {0xB4, _CopyBytes2Mod}, // LFS/r
    {0xB5, _CopyBytes2Mod}, // LGS/r
    {0xB6, _CopyBytes2Mod}, // MOVZX/r
    {0xB7, _CopyBytes2Mod}, // MOVZX/r
#ifdef DETOURS_X86
    {0xB8, _Copy0FB8}, // jmpe f3/popcnt
#else
    {0xB8, _CopyBytes2Mod},        // f3/popcnt
#endif
    {0xB9, _InvalidCopy},    // _B9
    {0xBA, _CopyBytes2Mod1}, // BT & BTC & BTR & BTS (0F BA)
    {0xBB, _CopyBytes2Mod},  // BTC (0F BB)
    {0xBC, _CopyBytes2Mod},  // BSF (0F BC)
    {0xBD, _CopyBytes2Mod},  // BSR (0F BD)
    {0xBE, _CopyBytes2Mod},  // MOVSX/r
    {0xBF, _CopyBytes2Mod},  // MOVSX/r
    {0xC0, _CopyBytes2Mod},  // XADD/r
    {0xC1, _CopyBytes2Mod},  // XADD/r
    {0xC2, _CopyBytes2Mod1}, // CMPPS &
    {0xC3, _CopyBytes2Mod},  // MOVNTI
    {0xC4, _CopyBytes2Mod1}, // PINSRW /r ib
    {0xC5, _CopyBytes2Mod1}, // PEXTRW /r ib
    {0xC6, _CopyBytes2Mod1}, // SHUFPS & SHUFPD
    {0xC7, _CopyBytes2Mod},  // CMPXCHG8B (0F C7)
    {0xC8, _CopyBytes1},     // BSWAP 0F C8 + rd
    {0xC9, _CopyBytes1},     // BSWAP 0F C8 + rd
    {0xCA, _CopyBytes1},     // BSWAP 0F C8 + rd
    {0xCB, _CopyBytes1},     // CVTPD2PI BSWAP 0F C8 + rd
    {0xCC, _CopyBytes1},     // BSWAP 0F C8 + rd
    {0xCD, _CopyBytes1},     // BSWAP 0F C8 + rd
    {0xCE, _CopyBytes1},     // BSWAP 0F C8 + rd
    {0xCF, _CopyBytes1},     // BSWAP 0F C8 + rd
    {0xD0, _CopyBytes2Mod},  // ADDSUBPS (untestd)
    {0xD1, _CopyBytes2Mod},  // PSRLW/r
    {0xD2, _CopyBytes2Mod},  // PSRLD/r
    {0xD3, _CopyBytes2Mod},  // PSRLQ/r
    {0xD4, _CopyBytes2Mod},  // PADDQ
    {0xD5, _CopyBytes2Mod},  // PMULLW/r
    {0xD6, _CopyBytes2Mod},  // MOVDQ2Q / MOVQ2DQ
    {0xD7, _CopyBytes2Mod},  // PMOVMSKB/r
    {0xD8, _CopyBytes2Mod},  // PSUBUSB/r
    {0xD9, _CopyBytes2Mod},  // PSUBUSW/r
    {0xDA, _CopyBytes2Mod},  // PMINUB/r
    {0xDB, _CopyBytes2Mod},  // PAND/r
    {0xDC, _CopyBytes2Mod},  // PADDUSB/r
    {0xDD, _CopyBytes2Mod},  // PADDUSW/r
    {0xDE, _CopyBytes2Mod},  // PMAXUB/r
    {0xDF, _CopyBytes2Mod},  // PANDN/r
    {0xE0, _CopyBytes2Mod},  // PAVGB
    {0xE1, _CopyBytes2Mod},  // PSRAW/r
    {0xE2, _CopyBytes2Mod},  // PSRAD/r
    {0xE3, _CopyBytes2Mod},  // PAVGW
    {0xE4, _CopyBytes2Mod},  // PMULHUW/r
    {0xE5, _CopyBytes2Mod},  // PMULHW/r
    {0xE6, _CopyBytes2Mod},  // CTDQ2PD &
    {0xE7, _CopyBytes2Mod},  // MOVNTQ
    {0xE8, _CopyBytes2Mod},  // PSUBB/r
    {0xE9, _CopyBytes2Mod},  // PSUBW/r
    {0xEA, _CopyBytes2Mod},  // PMINSW/r
    {0xEB, _CopyBytes2Mod},  // POR/r
    {0xEC, _CopyBytes2Mod},  // PADDSB/r
    {0xED, _CopyBytes2Mod},  // PADDSW/r
    {0xEE, _CopyBytes2Mod},  // PMAXSW /r
    {0xEF, _CopyBytes2Mod},  // PXOR/r
    {0xF0, _CopyBytes2Mod},  // LDDQU
    {0xF1, _CopyBytes2Mod},  // PSLLW/r
    {0xF2, _CopyBytes2Mod},  // PSLLD/r
    {0xF3, _CopyBytes2Mod},  // PSLLQ/r
    {0xF4, _CopyBytes2Mod},  // PMULUDQ/r
    {0xF5, _CopyBytes2Mod},  // PMADDWD/r
    {0xF6, _CopyBytes2Mod},  // PSADBW/r
    {0xF7, _CopyBytes2Mod},  // MASKMOVQ
    {0xF8, _CopyBytes2Mod},  // PSUBB/r
    {0xF9, _CopyBytes2Mod},  // PSUBW/r
    {0xFA, _CopyBytes2Mod},  // PSUBD/r
    {0xFB, _CopyBytes2Mod},  // FSUBQ/r
    {0xFC, _CopyBytes2Mod},  // PADDB/r
    {0xFD, _CopyBytes2Mod},  // PADDW/r
    {0xFE, _CopyBytes2Mod},  // PADDD/r
    {0xFF, _InvalidCopy},    // _FF
    {0, _EndCopy},
};
