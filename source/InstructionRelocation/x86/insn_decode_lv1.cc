
//////////////////////////////////////////////////// X86 and X64 Disassembler.
//
//  Includes full support for all x86 chips prior to the Pentium III, and some newer stuff.
//

#include <stdint.h>

typedef uint8_t BYTE;
typedef uint8_t* PBYTE;
typedef uintptr_t ULONG;
typedef intptr_t LONG;
typedef bool BOOL;
typedef void * PVOID;
typedef unsigned int UINT;

#define FALSE false
#define TRUE true

#define WINAPI

#if defined(DETOURS_X64) || defined(DETOURS_X86)

class CDetourDis {
public:
  CDetourDis(_Out_opt_ PBYTE *ppbTarget, _Out_opt_ LONG *plExtra);

  PBYTE CopyInstruction(PBYTE pbDst, PBYTE pbSrc);
  static BOOL SanityCheckSystem();
  static BOOL SetCodeModule(PBYTE pbBeg, PBYTE pbEnd, BOOL fLimitReferencesToModule);

public:
  struct COPYENTRY;
  typedef const COPYENTRY *REFCOPYENTRY;

  typedef PBYTE (CDetourDis::*COPYFUNC)(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

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

  struct COPYENTRY {
    // Many of these fields are often ignored. See ENTRY_DataIgnored.
    ULONG nFixedSize : 4;   // Fixed size of opcode
    ULONG nFixedSize16 : 4; // Fixed size when 16 bit operand
    ULONG nModOffset : 4;   // Offset to mod/rm byte (0=none)
    ULONG nRelOffset : 4;   // Offset to relative target.
    ULONG nFlagBits : 4;    // Flags for DYNAMIC, etc.
    COPYFUNC pfCopy;        // Function pointer.
  };

protected:
// These macros define common uses of nFixedSize, nFixedSize16, nModOffset, nRelOffset, nFlagBits, pfCopy.
#define ENTRY_DataIgnored 0, 0, 0, 0, 0,
#define ENTRY_CopyBytes1                                                                                               \
  { 1, 1, 0, 0, 0, &CDetourDis::CopyBytes }
#ifdef DETOURS_X64
#define ENTRY_CopyBytes1Address                                                                                        \
  { 9, 5, 0, 0, ADDRESS, &CDetourDis::CopyBytes }
#else
#define ENTRY_CopyBytes1Address                                                                                        \
  { 5, 3, 0, 0, ADDRESS, &CDetourDis::CopyBytes }
#endif
#define ENTRY_CopyBytes1Dynamic                                                                                        \
  { 1, 1, 0, 0, DYNAMIC, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes2                                                                                               \
  { 2, 2, 0, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes2Jump                                                                                           \
  { ENTRY_DataIgnored &CDetourDis::CopyBytesJump }
#define ENTRY_CopyBytes2CantJump                                                                                       \
  { 2, 2, 0, 1, NOENLARGE, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes2Dynamic                                                                                        \
  { 2, 2, 0, 0, DYNAMIC, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes3                                                                                               \
  { 3, 3, 0, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes3Dynamic                                                                                        \
  { 3, 3, 0, 0, DYNAMIC, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes3Or5                                                                                            \
  { 5, 3, 0, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes3Or5Dynamic                                                                                     \
  { 5, 3, 0, 0, DYNAMIC, &CDetourDis::CopyBytes } // x86 only
#ifdef DETOURS_X64
#define ENTRY_CopyBytes3Or5Rax                                                                                         \
  { 5, 3, 0, 0, RAX, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes3Or5Target                                                                                      \
  { 5, 5, 0, 1, 0, &CDetourDis::CopyBytes }
#else
#define ENTRY_CopyBytes3Or5Rax                                                                                         \
  { 5, 3, 0, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes3Or5Target                                                                                      \
  { 5, 3, 0, 1, 0, &CDetourDis::CopyBytes }
#endif
#define ENTRY_CopyBytes4                                                                                               \
  { 4, 4, 0, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes5                                                                                               \
  { 5, 5, 0, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes5Or7Dynamic                                                                                     \
  { 7, 5, 0, 0, DYNAMIC, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes7                                                                                               \
  { 7, 7, 0, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes2Mod                                                                                            \
  { 2, 2, 1, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes2ModDynamic                                                                                     \
  { 2, 2, 1, 0, DYNAMIC, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes2Mod1                                                                                           \
  { 3, 3, 1, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes2ModOperand                                                                                     \
  { 6, 4, 1, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes3Mod                                                                                            \
  { 3, 3, 2, 0, 0, &CDetourDis::CopyBytes } // SSE3 0F 38 opcode modrm
#define ENTRY_CopyBytes3Mod1                                                                                           \
  { 4, 4, 2, 0, 0, &CDetourDis::CopyBytes } // SSE3 0F 3A opcode modrm .. imm8
#define ENTRY_CopyBytesPrefix                                                                                          \
  { ENTRY_DataIgnored &CDetourDis::CopyBytesPrefix }
#define ENTRY_CopyBytesSegment                                                                                         \
  { ENTRY_DataIgnored &CDetourDis::CopyBytesSegment }
#define ENTRY_CopyBytesRax                                                                                             \
  { ENTRY_DataIgnored &CDetourDis::CopyBytesRax }
#define ENTRY_CopyF2                                                                                                   \
  { ENTRY_DataIgnored &CDetourDis::CopyF2 }
#define ENTRY_CopyF3                                                                                                   \
  { ENTRY_DataIgnored &CDetourDis::CopyF3 } // 32bit x86 only
#define ENTRY_Copy0F                                                                                                   \
  { ENTRY_DataIgnored &CDetourDis::Copy0F }
#define ENTRY_Copy0F78                                                                                                 \
  { ENTRY_DataIgnored &CDetourDis::Copy0F78 }
#define ENTRY_Copy0F00                                                                                                 \
  { ENTRY_DataIgnored &CDetourDis::Copy0F00 } // 32bit x86 only
#define ENTRY_Copy0FB8                                                                                                 \
  { ENTRY_DataIgnored &CDetourDis::Copy0FB8 } // 32bit x86 only
#define ENTRY_Copy66                                                                                                   \
  { ENTRY_DataIgnored &CDetourDis::Copy66 }
#define ENTRY_Copy67                                                                                                   \
  { ENTRY_DataIgnored &CDetourDis::Copy67 }
#define ENTRY_CopyF6                                                                                                   \
  { ENTRY_DataIgnored &CDetourDis::CopyF6 }
#define ENTRY_CopyF7                                                                                                   \
  { ENTRY_DataIgnored &CDetourDis::CopyF7 }
#define ENTRY_CopyFF                                                                                                   \
  { ENTRY_DataIgnored &CDetourDis::CopyFF }
#define ENTRY_CopyVex2                                                                                                 \
  { ENTRY_DataIgnored &CDetourDis::CopyVex2 }
#define ENTRY_CopyVex3                                                                                                 \
  { ENTRY_DataIgnored &CDetourDis::CopyVex3 }
#define ENTRY_CopyEvex                                                                                                 \
  { ENTRY_DataIgnored &CDetourDis::CopyEvex } // 62, 3 byte payload, then normal with implied prefixes like vex
#define ENTRY_CopyXop                                                                                                  \
  { ENTRY_DataIgnored &CDetourDis::CopyXop } // 0x8F ... POP /0 or AMD XOP
#define ENTRY_CopyBytesXop                                                                                             \
  { 5, 5, 4, 0, 0, &CDetourDis::CopyBytes } // 0x8F xop1 xop2 opcode modrm
#define ENTRY_CopyBytesXop1                                                                                            \
  { 6, 6, 4, 0, 0, &CDetourDis::CopyBytes } // 0x8F xop1 xop2 opcode modrm ... imm8
#define ENTRY_CopyBytesXop4                                                                                            \
  { 9, 9, 4, 0, 0, &CDetourDis::CopyBytes } // 0x8F xop1 xop2 opcode modrm ... imm32
#define ENTRY_Invalid                                                                                                  \
  { ENTRY_DataIgnored &CDetourDis::Invalid }

  PBYTE CopyBytes(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyBytesPrefix(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyBytesSegment(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyBytesRax(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyBytesJump(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

  PBYTE Invalid(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

  PBYTE AdjustTarget(PBYTE pbDst, PBYTE pbSrc, UINT cbOp, UINT cbTargetOffset, UINT cbTargetSize);

protected:
  PBYTE Copy0F(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE Copy0F00(REFCOPYENTRY pEntry, PBYTE pbDst,
                 PBYTE pbSrc); // x86 only sldt/0 str/1 lldt/2 ltr/3 err/4 verw/5 jmpe/6/dynamic invalid/7
  PBYTE Copy0F78(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc); // vmread, 66/extrq/ib/ib, F2/insertq/ib/ib
  PBYTE Copy0FB8(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc); // jmpe or F3/popcnt
  PBYTE Copy66(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE Copy67(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyF2(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyF3(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc); // x86 only
  PBYTE CopyF6(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyF7(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyFF(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyVex2(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyVex3(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyVexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyVexEvexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc, BYTE p);
  PBYTE CopyEvex(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
  PBYTE CopyXop(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

protected:
  static const COPYENTRY s_rceCopyTable[];
  static const COPYENTRY s_rceCopyTable0F[];
  static const BYTE s_rbModRm[256];
  static PBYTE s_pbModuleBeg;
  static PBYTE s_pbModuleEnd;
  static BOOL s_fLimitReferencesToModule;

protected:
  BOOL m_bOperandOverride;
  BOOL m_bAddressOverride;
  BOOL m_bRaxOverride; // AMD64 only
  BOOL m_bVex;
  BOOL m_bEvex;
  BOOL m_bF2;
  BOOL m_bF3; // x86 only
  BYTE m_nSegmentOverride;

  PBYTE *m_ppbTarget;
  LONG *m_plExtra;

  LONG m_lScratchExtra;
  PBYTE m_pbScratchTarget;
  BYTE m_rbScratchDst[64]; // matches or exceeds rbCode
};

PVOID WINAPI DetourCopyInstruction(_In_opt_ PVOID pDst, _Inout_opt_ PVOID *ppDstPool, _In_ PVOID pSrc,
                                   _Out_opt_ PVOID *ppTarget, _Out_opt_ LONG *plExtra) {
  UNREFERENCED_PARAMETER(ppDstPool); // x86 & x64 don't use a constant pool.

  CDetourDis oDetourDisasm((PBYTE *)ppTarget, plExtra);
  return oDetourDisasm.CopyInstruction((PBYTE)pDst, (PBYTE)pSrc);
}

/////////////////////////////////////////////////////////// Disassembler Code.
//
CDetourDis::CDetourDis(_Out_opt_ PBYTE *ppbTarget, _Out_opt_ LONG *plExtra)
    : m_bOperandOverride(FALSE), m_bAddressOverride(FALSE), m_bRaxOverride(FALSE), m_bF2(FALSE), m_bF3(FALSE),
      m_bVex(FALSE), m_bEvex(FALSE) {
  m_ppbTarget = ppbTarget ? ppbTarget : &m_pbScratchTarget;
  m_plExtra   = plExtra ? plExtra : &m_lScratchExtra;

  *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_NONE;
  *m_plExtra   = 0;
}

PBYTE CDetourDis::CopyInstruction(PBYTE pbDst, PBYTE pbSrc) {
  // Configure scratch areas if real areas are not available.
  if (NULL == pbDst) {
    pbDst = m_rbScratchDst;
  }
  if (NULL == pbSrc) {
    // We can't copy a non-existent instruction.
    SetLastError(ERROR_INVALID_DATA);
    return NULL;
  }

  // Figure out how big the instruction is, do the appropriate copy,
  // and figure out what the target of the instruction is if any.
  //
  REFCOPYENTRY pEntry = &s_rceCopyTable[pbSrc[0]];
  return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyBytes(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc) {
  UINT nBytesFixed;

  if (m_bVex || m_bEvex) {
    ASSERT(pEntry->nFlagBits == 0);
    ASSERT(pEntry->nFixedSize == pEntry->nFixedSize16);
  }

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

    if (bFlags & SIB) {
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
    *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
  }
  return pbSrc + nBytes;
}

PBYTE CDetourDis::CopyBytesPrefix(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc) {
  pbDst[0] = pbSrc[0];
  pEntry   = &s_rceCopyTable[pbSrc[1]];
  return (this->*pEntry->pfCopy)(pEntry, pbDst + 1, pbSrc + 1);
}

PBYTE CDetourDis::CopyBytesSegment(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc) {
  m_nSegmentOverride = pbSrc[0];
  return CopyBytesPrefix(0, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyBytesRax(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc) { // AMD64 only
  if (pbSrc[0] & 0x8) {
    m_bRaxOverride = TRUE;
  }
  return CopyBytesPrefix(0, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyBytesJump(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc) {
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

PBYTE CDetourDis::AdjustTarget(PBYTE pbDst, PBYTE pbSrc, UINT cbOp, UINT cbTargetOffset, UINT cbTargetSize) {
  PBYTE pbTarget = NULL;
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
      *m_plExtra = sizeof(ULONG) - 1;
    }
    break;
  case 2:
    *(UNALIGNED SHORT *&)pvTargetAddr = (SHORT)nNewOffset;
    if (nNewOffset < SHRT_MIN || nNewOffset > SHRT_MAX) {
      *m_plExtra = sizeof(ULONG) - 2;
    }
    break;
  case 4:
    *(UNALIGNED LONG *&)pvTargetAddr = (LONG)nNewOffset;
    if (nNewOffset < LONG_MIN || nNewOffset > LONG_MAX) {
      *m_plExtra = sizeof(ULONG) - 4;
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

PBYTE CDetourDis::Invalid(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc) {
  (void)pbDst;
  (void)pEntry;
  ASSERT(!"Invalid Instruction");
  return pbSrc + 1;
}

////////////////////////////////////////////////////// Individual Bytes Codes.
//
PBYTE CDetourDis::Copy0F(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc) {
  pbDst[0] = pbSrc[0];
  pEntry   = &s_rceCopyTable0F[pbSrc[1]];
  return (this->*pEntry->pfCopy)(pEntry, pbDst + 1, pbSrc + 1);
}

PBYTE CDetourDis::Copy0F78(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc) {
  // vmread, 66/extrq, F2/insertq

  static const COPYENTRY vmread        = /* 78 */ ENTRY_CopyBytes2Mod;
  static const COPYENTRY extrq_insertq = /* 78 */ ENTRY_CopyBytes4;

  ASSERT(!(m_bF2 && m_bOperandOverride));

  // For insertq and presumably despite documentation extrq, mode must be 11, not checked.
  // insertq/extrq/78 are followed by two immediate bytes, and given mode == 11, mod/rm byte is always one byte,
  // and the 0x78 makes 4 bytes (not counting the 66/F2/F which are accounted for elsewhere)

  REFCOPYENTRY const pEntry = ((m_bF2 || m_bOperandOverride) ? &extrq_insertq : &vmread);

  return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::Copy0F00(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc) {
  // jmpe is 32bit x86 only
  // Notice that the sizes are the same either way, but jmpe is marked as "dynamic".

  static const COPYENTRY other =
      /* B8 */ ENTRY_CopyBytes2Mod; // sldt/0 str/1 lldt/2 ltr/3 err/4 verw/5 jmpe/6 invalid/7
  static const COPYENTRY jmpe = /* B8 */ ENTRY_CopyBytes2ModDynamic; // jmpe/6 x86-on-IA64 syscalls

  REFCOPYENTRY const pEntry = (((6 << 3) == ((7 << 3) & pbSrc[1])) ? &jmpe : &other);
  return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::Copy0FB8(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc) {
  // jmpe is 32bit x86 only

  static const COPYENTRY popcnt = /* B8 */ ENTRY_CopyBytes2Mod;
  static const COPYENTRY jmpe   = /* B8 */ ENTRY_CopyBytes3Or5Dynamic; // jmpe x86-on-IA64 syscalls
  REFCOPYENTRY const pEntry     = m_bF3 ? &popcnt : &jmpe;
  return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::Copy66(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc) { // Operand-size override prefix
  m_bOperandOverride = TRUE;
  return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::Copy67(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc) { // Address size override prefix
  m_bAddressOverride = TRUE;
  return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF2(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc) {
  m_bF2 = TRUE;
  return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF3(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc) { // x86 only
  m_bF3 = TRUE;
  return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF6(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc) {
  (void)pEntry;

  // TEST BYTE /0
  if (0x00 == (0x38 & pbSrc[1])) { // reg(bits 543) of ModR/M == 0
    static const COPYENTRY ce = /* f6 */ ENTRY_CopyBytes2Mod1;
    return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
  }
  // DIV /6
  // IDIV /7
  // IMUL /5
  // MUL /4
  // NEG /3
  // NOT /2

  static const COPYENTRY ce = /* f6 */ ENTRY_CopyBytes2Mod;
  return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF7(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc) {
  (void)pEntry;

  // TEST WORD /0
  if (0x00 == (0x38 & pbSrc[1])) { // reg(bits 543) of ModR/M == 0
    static const COPYENTRY ce = /* f7 */ ENTRY_CopyBytes2ModOperand;
    return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
  }

  // DIV /6
  // IDIV /7
  // IMUL /5
  // MUL /4
  // NEG /3
  // NOT /2
  static const COPYENTRY ce = /* f7 */ ENTRY_CopyBytes2Mod;
  return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyFF(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc) { // INC /0
  // DEC /1
  // CALL /2
  // CALL /3
  // JMP /4
  // JMP /5
  // PUSH /6
  // invalid/7
  (void)pEntry;

  static const COPYENTRY ce = /* ff */ ENTRY_CopyBytes2Mod;
  PBYTE pbOut               = (this->*ce.pfCopy)(&ce, pbDst, pbSrc);

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
      PBYTE *ppbTarget = (PBYTE *)(pbSrc + 6 + offset);
#else
      PBYTE *ppbTarget = (PBYTE *)(SIZE_T) * (UNALIGNED ULONG *)&pbSrc[2];
#endif
      if (s_fLimitReferencesToModule && (ppbTarget < (PVOID)s_pbModuleBeg || ppbTarget >= (PVOID)s_pbModuleEnd)) {

        *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
      } else {
        // This can access violate on random bytes. Use DetourSetCodeModule.
        *m_ppbTarget = *ppbTarget;
      }
    } else {
      *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
    }
  } else if (0x10 == (0x30 & b1) || // CALL /2 or /3  --> reg(bits 543) of ModR/M == 010 or 011
             0x20 == (0x30 & b1)) { // JMP /4 or /5 --> reg(bits 543) of ModR/M == 100 or 101
    *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
  }
  return pbOut;
}

PBYTE CDetourDis::CopyVexEvexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc, BYTE p)
// m is first instead of last in the hopes of pbDst/pbSrc being
// passed along efficiently in the registers they were already in.
{
  static const COPYENTRY ceF38     = /* 38 */ ENTRY_CopyBytes2Mod;
  static const COPYENTRY ceF3A     = /* 3A */ ENTRY_CopyBytes2Mod1;
  static const COPYENTRY ceInvalid = /* C4 */ ENTRY_Invalid;

  switch (p & 3) {
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

  REFCOPYENTRY pEntry;

  switch (m) {
  default:
    return Invalid(&ceInvalid, pbDst, pbSrc);
  case 1:
    pEntry = &s_rceCopyTable0F[pbSrc[0]];
    return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
  case 2:
    return CopyBytes(&ceF38, pbDst, pbSrc);
  case 3:
    return CopyBytes(&ceF3A, pbDst, pbSrc);
  }
}

PBYTE CDetourDis::CopyVexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc)
// m is first instead of last in the hopes of pbDst/pbSrc being
// passed along efficiently in the registers they were already in.
{
  m_bVex       = TRUE;
  BYTE const p = (BYTE)(pbSrc[-1] & 3); // p in last byte
  return CopyVexEvexCommon(m, pbDst, pbSrc, p);
}

PBYTE CDetourDis::CopyVex3(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
// 3 byte VEX prefix 0xC4
{
#ifdef DETOURS_X86
  const static COPYENTRY ceLES = /* C4 */ ENTRY_CopyBytes2Mod;
  if ((pbSrc[1] & 0xC0) != 0xC0) {
    REFCOPYENTRY pEntry = &ceLES;
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

PBYTE CDetourDis::CopyVex2(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
// 2 byte VEX prefix 0xC5
{
#ifdef DETOURS_X86
  const static COPYENTRY ceLDS = /* C5 */ ENTRY_CopyBytes2Mod;
  if ((pbSrc[1] & 0xC0) != 0xC0) {
    REFCOPYENTRY pEntry = &ceLDS;
    return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
  }
#endif
  pbDst[0] = pbSrc[0];
  pbDst[1] = pbSrc[1];
  return CopyVexCommon(1, pbDst + 2, pbSrc + 2);
}

PBYTE CDetourDis::CopyEvex(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
// 62, 3 byte payload, x86 with implied prefixes like Vex
// for 32bit, mode 0xC0 else fallback to bound /r
{
  // NOTE: Intel and Wikipedia number these differently.
  // Intel says 0-2, Wikipedia says 1-3.

  BYTE const p0 = pbSrc[1];

#ifdef DETOURS_X86
  const static COPYENTRY ceBound = /* 62 */ ENTRY_CopyBytes2Mod;
  if ((p0 & 0xC0) != 0xC0) {
    return CopyBytes(&ceBound, pbDst, pbSrc);
  }
#endif

  static const COPYENTRY ceInvalid = /* 62 */ ENTRY_Invalid;

  if ((p0 & 0x0C) != 0)
    return Invalid(&ceInvalid, pbDst, pbSrc);

  BYTE const p1 = pbSrc[2];

  if ((p1 & 0x04) != 0x04)
    return Invalid(&ceInvalid, pbDst, pbSrc);

  // Copy 4 byte prefix.
  *(UNALIGNED ULONG *)pbDst = *(UNALIGNED ULONG *)pbSrc;

  m_bEvex = TRUE;

#ifdef DETOURS_X64
  m_bRaxOverride |= !!(p1 & 0x80); // w
#endif

  return CopyVexEvexCommon(p0 & 3u, pbDst + 4, pbSrc + 4, p1 & 3u);
}

PBYTE CDetourDis::CopyXop(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
/* 3 byte AMD XOP prefix 0x8F
byte0: 0x8F
byte1: RXBmmmmm
byte2: WvvvvLpp
byte3: opcode
mmmmm >= 8, else pop
mmmmm only otherwise defined for 8, 9, A.
pp is like VEX but only instructions with 0 are defined
*/
{
  const static COPYENTRY cePop  = /* 8F */ ENTRY_CopyBytes2Mod;
  const static COPYENTRY ceXop  = /* 8F */ ENTRY_CopyBytesXop;
  const static COPYENTRY ceXop1 = /* 8F */ ENTRY_CopyBytesXop1;
  const static COPYENTRY ceXop4 = /* 8F */ ENTRY_CopyBytesXop4;

  BYTE const m = (BYTE)(pbSrc[1] & 0x1F);
  ASSERT(m <= 10);
  switch (m) {
  default:
    return CopyBytes(&cePop, pbDst, pbSrc);

  case 8: // modrm with 8bit immediate
    return CopyBytes(&ceXop1, pbDst, pbSrc);

  case 9: // modrm with no immediate
    return CopyBytes(&ceXop, pbDst, pbSrc);

  case 10: // modrm with 32bit immediate
    return CopyBytes(&ceXop4, pbDst, pbSrc);
  }
}

//////////////////////////////////////////////////////////////////////////////
//
PBYTE CDetourDis::s_pbModuleBeg             = NULL;
PBYTE CDetourDis::s_pbModuleEnd             = (PBYTE) ~(ULONG_PTR)0;
BOOL CDetourDis::s_fLimitReferencesToModule = FALSE;

BOOL CDetourDis::SetCodeModule(PBYTE pbBeg, PBYTE pbEnd, BOOL fLimitReferencesToModule) {
  if (pbEnd < pbBeg) {
    return FALSE;
  }

  s_pbModuleBeg              = pbBeg;
  s_pbModuleEnd              = pbEnd;
  s_fLimitReferencesToModule = fLimitReferencesToModule;

  return TRUE;
}

///////////////////////////////////////////////////////// Disassembler Tables.
//
const BYTE CDetourDis::s_rbModRm[256] = {
    0, 0, 0, 0, SIB | 1, RIP | 4, 0, 0, 0, 0, 0, 0, SIB | 1, RIP | 4, 0, 0, // 0x
    0, 0, 0, 0, SIB | 1, RIP | 4, 0, 0, 0, 0, 0, 0, SIB | 1, RIP | 4, 0, 0, // 1x
    0, 0, 0, 0, SIB | 1, RIP | 4, 0, 0, 0, 0, 0, 0, SIB | 1, RIP | 4, 0, 0, // 2x
    0, 0, 0, 0, SIB | 1, RIP | 4, 0, 0, 0, 0, 0, 0, SIB | 1, RIP | 4, 0, 0, // 3x
    1, 1, 1, 1, 2,       1,       1, 1, 1, 1, 1, 1, 2,       1,       1, 1, // 4x
    1, 1, 1, 1, 2,       1,       1, 1, 1, 1, 1, 1, 2,       1,       1, 1, // 5x
    1, 1, 1, 1, 2,       1,       1, 1, 1, 1, 1, 1, 2,       1,       1, 1, // 6x
    1, 1, 1, 1, 2,       1,       1, 1, 1, 1, 1, 1, 2,       1,       1, 1, // 7x
    4, 4, 4, 4, 5,       4,       4, 4, 4, 4, 4, 4, 5,       4,       4, 4, // 8x
    4, 4, 4, 4, 5,       4,       4, 4, 4, 4, 4, 4, 5,       4,       4, 4, // 9x
    4, 4, 4, 4, 5,       4,       4, 4, 4, 4, 4, 4, 5,       4,       4, 4, // Ax
    4, 4, 4, 4, 5,       4,       4, 4, 4, 4, 4, 4, 5,       4,       4, 4, // Bx
    0, 0, 0, 0, 0,       0,       0, 0, 0, 0, 0, 0, 0,       0,       0, 0, // Cx
    0, 0, 0, 0, 0,       0,       0, 0, 0, 0, 0, 0, 0,       0,       0, 0, // Dx
    0, 0, 0, 0, 0,       0,       0, 0, 0, 0, 0, 0, 0,       0,       0, 0, // Ex
    0, 0, 0, 0, 0,       0,       0, 0, 0, 0, 0, 0, 0,       0,       0, 0  // Fx
};

const CDetourDis::COPYENTRY CDetourDis::s_rceCopyTable[] = {
    /* 00 */ ENTRY_CopyBytes2Mod, // ADD /r
    /* 01 */ ENTRY_CopyBytes2Mod, // ADD /r
    /* 02 */ ENTRY_CopyBytes2Mod, // ADD /r
    /* 03 */ ENTRY_CopyBytes2Mod, // ADD /r
    /* 04 */ ENTRY_CopyBytes2,    // ADD ib
    /* 05 */ ENTRY_CopyBytes3Or5, // ADD iw
#ifdef DETOURS_X64
    /* 06 */ ENTRY_Invalid, // Invalid
    /* 07 */ ENTRY_Invalid, // Invalid
#else
    /* 06 */ ENTRY_CopyBytes1, // PUSH
    /* 07 */ ENTRY_CopyBytes1, // POP
#endif
    /* 08 */ ENTRY_CopyBytes2Mod, // OR /r
    /* 09 */ ENTRY_CopyBytes2Mod, // OR /r
    /* 0A */ ENTRY_CopyBytes2Mod, // OR /r
    /* 0B */ ENTRY_CopyBytes2Mod, // OR /r
    /* 0C */ ENTRY_CopyBytes2,    // OR ib
    /* 0D */ ENTRY_CopyBytes3Or5, // OR iw
#ifdef DETOURS_X64
    /* 0E */ ENTRY_Invalid, // Invalid
#else
    /* 0E */ ENTRY_CopyBytes1, // PUSH
#endif
    /* 0F */ ENTRY_Copy0F,        // Extension Ops
    /* 10 */ ENTRY_CopyBytes2Mod, // ADC /r
    /* 11 */ ENTRY_CopyBytes2Mod, // ADC /r
    /* 12 */ ENTRY_CopyBytes2Mod, // ADC /r
    /* 13 */ ENTRY_CopyBytes2Mod, // ADC /r
    /* 14 */ ENTRY_CopyBytes2,    // ADC ib
    /* 15 */ ENTRY_CopyBytes3Or5, // ADC id
#ifdef DETOURS_X64
    /* 16 */ ENTRY_Invalid, // Invalid
    /* 17 */ ENTRY_Invalid, // Invalid
#else
    /* 16 */ ENTRY_CopyBytes1, // PUSH
    /* 17 */ ENTRY_CopyBytes1, // POP
#endif
    /* 18 */ ENTRY_CopyBytes2Mod, // SBB /r
    /* 19 */ ENTRY_CopyBytes2Mod, // SBB /r
    /* 1A */ ENTRY_CopyBytes2Mod, // SBB /r
    /* 1B */ ENTRY_CopyBytes2Mod, // SBB /r
    /* 1C */ ENTRY_CopyBytes2,    // SBB ib
    /* 1D */ ENTRY_CopyBytes3Or5, // SBB id
#ifdef DETOURS_X64
    /* 1E */ ENTRY_Invalid, // Invalid
    /* 1F */ ENTRY_Invalid, // Invalid
#else
    /* 1E */ ENTRY_CopyBytes1, // PUSH
    /* 1F */ ENTRY_CopyBytes1, // POP
#endif
    /* 20 */ ENTRY_CopyBytes2Mod,    // AND /r
    /* 21 */ ENTRY_CopyBytes2Mod,    // AND /r
    /* 22 */ ENTRY_CopyBytes2Mod,    // AND /r
    /* 23 */ ENTRY_CopyBytes2Mod,    // AND /r
    /* 24 */ ENTRY_CopyBytes2,       // AND ib
    /* 25 */ ENTRY_CopyBytes3Or5,    // AND id
    /* 26 */ ENTRY_CopyBytesSegment, // ES prefix
#ifdef DETOURS_X64
    /* 27 */ ENTRY_Invalid, // Invalid
#else
    /* 27 */ ENTRY_CopyBytes1, // DAA
#endif
    /* 28 */ ENTRY_CopyBytes2Mod,    // SUB /r
    /* 29 */ ENTRY_CopyBytes2Mod,    // SUB /r
    /* 2A */ ENTRY_CopyBytes2Mod,    // SUB /r
    /* 2B */ ENTRY_CopyBytes2Mod,    // SUB /r
    /* 2C */ ENTRY_CopyBytes2,       // SUB ib
    /* 2D */ ENTRY_CopyBytes3Or5,    // SUB id
    /* 2E */ ENTRY_CopyBytesSegment, // CS prefix
#ifdef DETOURS_X64
    /* 2F */ ENTRY_Invalid, // Invalid
#else
    /* 2F */ ENTRY_CopyBytes1, // DAS
#endif
    /* 30 */ ENTRY_CopyBytes2Mod,    // XOR /r
    /* 31 */ ENTRY_CopyBytes2Mod,    // XOR /r
    /* 32 */ ENTRY_CopyBytes2Mod,    // XOR /r
    /* 33 */ ENTRY_CopyBytes2Mod,    // XOR /r
    /* 34 */ ENTRY_CopyBytes2,       // XOR ib
    /* 35 */ ENTRY_CopyBytes3Or5,    // XOR id
    /* 36 */ ENTRY_CopyBytesSegment, // SS prefix
#ifdef DETOURS_X64
    /* 37 */ ENTRY_Invalid, // Invalid
#else
    /* 37 */ ENTRY_CopyBytes1, // AAA
#endif
    /* 38 */ ENTRY_CopyBytes2Mod,    // CMP /r
    /* 39 */ ENTRY_CopyBytes2Mod,    // CMP /r
    /* 3A */ ENTRY_CopyBytes2Mod,    // CMP /r
    /* 3B */ ENTRY_CopyBytes2Mod,    // CMP /r
    /* 3C */ ENTRY_CopyBytes2,       // CMP ib
    /* 3D */ ENTRY_CopyBytes3Or5,    // CMP id
    /* 3E */ ENTRY_CopyBytesSegment, // DS prefix
#ifdef DETOURS_X64
    /* 3F */ ENTRY_Invalid, // Invalid
#else
    /* 3F */ ENTRY_CopyBytes1, // AAS
#endif
#ifdef DETOURS_X64 // For Rax Prefix
    /* 40 */ ENTRY_CopyBytesRax, // Rax
    /* 41 */ ENTRY_CopyBytesRax, // Rax
    /* 42 */ ENTRY_CopyBytesRax, // Rax
    /* 43 */ ENTRY_CopyBytesRax, // Rax
    /* 44 */ ENTRY_CopyBytesRax, // Rax
    /* 45 */ ENTRY_CopyBytesRax, // Rax
    /* 46 */ ENTRY_CopyBytesRax, // Rax
    /* 47 */ ENTRY_CopyBytesRax, // Rax
    /* 48 */ ENTRY_CopyBytesRax, // Rax
    /* 49 */ ENTRY_CopyBytesRax, // Rax
    /* 4A */ ENTRY_CopyBytesRax, // Rax
    /* 4B */ ENTRY_CopyBytesRax, // Rax
    /* 4C */ ENTRY_CopyBytesRax, // Rax
    /* 4D */ ENTRY_CopyBytesRax, // Rax
    /* 4E */ ENTRY_CopyBytesRax, // Rax
    /* 4F */ ENTRY_CopyBytesRax, // Rax
#else
    /* 40 */ ENTRY_CopyBytes1, // INC
    /* 41 */ ENTRY_CopyBytes1, // INC
    /* 42 */ ENTRY_CopyBytes1, // INC
    /* 43 */ ENTRY_CopyBytes1, // INC
    /* 44 */ ENTRY_CopyBytes1, // INC
    /* 45 */ ENTRY_CopyBytes1, // INC
    /* 46 */ ENTRY_CopyBytes1, // INC
    /* 47 */ ENTRY_CopyBytes1, // INC
    /* 48 */ ENTRY_CopyBytes1, // DEC
    /* 49 */ ENTRY_CopyBytes1, // DEC
    /* 4A */ ENTRY_CopyBytes1, // DEC
    /* 4B */ ENTRY_CopyBytes1, // DEC
    /* 4C */ ENTRY_CopyBytes1, // DEC
    /* 4D */ ENTRY_CopyBytes1, // DEC
    /* 4E */ ENTRY_CopyBytes1, // DEC
    /* 4F */ ENTRY_CopyBytes1, // DEC
#endif
    /* 50 */ ENTRY_CopyBytes1, // PUSH
    /* 51 */ ENTRY_CopyBytes1, // PUSH
    /* 52 */ ENTRY_CopyBytes1, // PUSH
    /* 53 */ ENTRY_CopyBytes1, // PUSH
    /* 54 */ ENTRY_CopyBytes1, // PUSH
    /* 55 */ ENTRY_CopyBytes1, // PUSH
    /* 56 */ ENTRY_CopyBytes1, // PUSH
    /* 57 */ ENTRY_CopyBytes1, // PUSH
    /* 58 */ ENTRY_CopyBytes1, // POP
    /* 59 */ ENTRY_CopyBytes1, // POP
    /* 5A */ ENTRY_CopyBytes1, // POP
    /* 5B */ ENTRY_CopyBytes1, // POP
    /* 5C */ ENTRY_CopyBytes1, // POP
    /* 5D */ ENTRY_CopyBytes1, // POP
    /* 5E */ ENTRY_CopyBytes1, // POP
    /* 5F */ ENTRY_CopyBytes1, // POP
#ifdef DETOURS_X64
    /* 60 */ ENTRY_Invalid,  // Invalid
    /* 61 */ ENTRY_Invalid,  // Invalid
    /* 62 */ ENTRY_CopyEvex, // EVEX / AVX512
#else
    /* 60 */ ENTRY_CopyBytes1, // PUSHAD
    /* 61 */ ENTRY_CopyBytes1, // POPAD
    /* 62 */ ENTRY_CopyEvex,   // BOUND /r and EVEX / AVX512
#endif
    /* 63 */ ENTRY_CopyBytes2Mod,        // 32bit ARPL /r, 64bit MOVSXD
    /* 64 */ ENTRY_CopyBytesSegment,     // FS prefix
    /* 65 */ ENTRY_CopyBytesSegment,     // GS prefix
    /* 66 */ ENTRY_Copy66,               // Operand Prefix
    /* 67 */ ENTRY_Copy67,               // Address Prefix
    /* 68 */ ENTRY_CopyBytes3Or5,        // PUSH
    /* 69 */ ENTRY_CopyBytes2ModOperand, // IMUL /r iz
    /* 6A */ ENTRY_CopyBytes2,           // PUSH
    /* 6B */ ENTRY_CopyBytes2Mod1,       // IMUL /r ib
    /* 6C */ ENTRY_CopyBytes1,           // INS
    /* 6D */ ENTRY_CopyBytes1,           // INS
    /* 6E */ ENTRY_CopyBytes1,           // OUTS/OUTSB
    /* 6F */ ENTRY_CopyBytes1,           // OUTS/OUTSW
    /* 70 */ ENTRY_CopyBytes2Jump,       // JO           // 0f80
    /* 71 */ ENTRY_CopyBytes2Jump,       // JNO          // 0f81
    /* 72 */ ENTRY_CopyBytes2Jump,       // JB/JC/JNAE   // 0f82
    /* 73 */ ENTRY_CopyBytes2Jump,       // JAE/JNB/JNC  // 0f83
    /* 74 */ ENTRY_CopyBytes2Jump,       // JE/JZ        // 0f84
    /* 75 */ ENTRY_CopyBytes2Jump,       // JNE/JNZ      // 0f85
    /* 76 */ ENTRY_CopyBytes2Jump,       // JBE/JNA      // 0f86
    /* 77 */ ENTRY_CopyBytes2Jump,       // JA/JNBE      // 0f87
    /* 78 */ ENTRY_CopyBytes2Jump,       // JS           // 0f88
    /* 79 */ ENTRY_CopyBytes2Jump,       // JNS          // 0f89
    /* 7A */ ENTRY_CopyBytes2Jump,       // JP/JPE       // 0f8a
    /* 7B */ ENTRY_CopyBytes2Jump,       // JNP/JPO      // 0f8b
    /* 7C */ ENTRY_CopyBytes2Jump,       // JL/JNGE      // 0f8c
    /* 7D */ ENTRY_CopyBytes2Jump,       // JGE/JNL      // 0f8d
    /* 7E */ ENTRY_CopyBytes2Jump,       // JLE/JNG      // 0f8e
    /* 7F */ ENTRY_CopyBytes2Jump,       // JG/JNLE      // 0f8f
    /* 80 */ ENTRY_CopyBytes2Mod1,       // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 byte reg, immediate byte
                                         /* 81 */
    ENTRY_CopyBytes2ModOperand, // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 byte reg, immediate word or dword
#ifdef DETOURS_X64
    /* 82 */ ENTRY_Invalid, // Invalid
#else
    /* 82 */ ENTRY_CopyBytes2Mod1, // MOV al,x
#endif
    /* 83 */ ENTRY_CopyBytes2Mod1, // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 reg, immediate byte
    /* 84 */ ENTRY_CopyBytes2Mod,  // TEST /r
    /* 85 */ ENTRY_CopyBytes2Mod,  // TEST /r
    /* 86 */ ENTRY_CopyBytes2Mod,  // XCHG /r @todo
    /* 87 */ ENTRY_CopyBytes2Mod,  // XCHG /r @todo
    /* 88 */ ENTRY_CopyBytes2Mod,  // MOV /r
    /* 89 */ ENTRY_CopyBytes2Mod,  // MOV /r
    /* 8A */ ENTRY_CopyBytes2Mod,  // MOV /r
    /* 8B */ ENTRY_CopyBytes2Mod,  // MOV /r
    /* 8C */ ENTRY_CopyBytes2Mod,  // MOV /r
    /* 8D */ ENTRY_CopyBytes2Mod,  // LEA /r
    /* 8E */ ENTRY_CopyBytes2Mod,  // MOV /r
    /* 8F */ ENTRY_CopyXop,        // POP /0 or AMD XOP
    /* 90 */ ENTRY_CopyBytes1,     // NOP
    /* 91 */ ENTRY_CopyBytes1,     // XCHG
    /* 92 */ ENTRY_CopyBytes1,     // XCHG
    /* 93 */ ENTRY_CopyBytes1,     // XCHG
    /* 94 */ ENTRY_CopyBytes1,     // XCHG
    /* 95 */ ENTRY_CopyBytes1,     // XCHG
    /* 96 */ ENTRY_CopyBytes1,     // XCHG
    /* 97 */ ENTRY_CopyBytes1,     // XCHG
    /* 98 */ ENTRY_CopyBytes1,     // CWDE
    /* 99 */ ENTRY_CopyBytes1,     // CDQ
#ifdef DETOURS_X64
    /* 9A */ ENTRY_Invalid, // Invalid
#else
    /* 9A */ ENTRY_CopyBytes5Or7Dynamic, // CALL cp
#endif
    /* 9B */ ENTRY_CopyBytes1,           // WAIT/FWAIT
    /* 9C */ ENTRY_CopyBytes1,           // PUSHFD
    /* 9D */ ENTRY_CopyBytes1,           // POPFD
    /* 9E */ ENTRY_CopyBytes1,           // SAHF
    /* 9F */ ENTRY_CopyBytes1,           // LAHF
    /* A0 */ ENTRY_CopyBytes1Address,    // MOV
    /* A1 */ ENTRY_CopyBytes1Address,    // MOV
    /* A2 */ ENTRY_CopyBytes1Address,    // MOV
    /* A3 */ ENTRY_CopyBytes1Address,    // MOV
    /* A4 */ ENTRY_CopyBytes1,           // MOVS
    /* A5 */ ENTRY_CopyBytes1,           // MOVS/MOVSD
    /* A6 */ ENTRY_CopyBytes1,           // CMPS/CMPSB
    /* A7 */ ENTRY_CopyBytes1,           // CMPS/CMPSW
    /* A8 */ ENTRY_CopyBytes2,           // TEST
    /* A9 */ ENTRY_CopyBytes3Or5,        // TEST
    /* AA */ ENTRY_CopyBytes1,           // STOS/STOSB
    /* AB */ ENTRY_CopyBytes1,           // STOS/STOSW
    /* AC */ ENTRY_CopyBytes1,           // LODS/LODSB
    /* AD */ ENTRY_CopyBytes1,           // LODS/LODSW
    /* AE */ ENTRY_CopyBytes1,           // SCAS/SCASB
    /* AF */ ENTRY_CopyBytes1,           // SCAS/SCASD
    /* B0 */ ENTRY_CopyBytes2,           // MOV B0+rb
    /* B1 */ ENTRY_CopyBytes2,           // MOV B0+rb
    /* B2 */ ENTRY_CopyBytes2,           // MOV B0+rb
    /* B3 */ ENTRY_CopyBytes2,           // MOV B0+rb
    /* B4 */ ENTRY_CopyBytes2,           // MOV B0+rb
    /* B5 */ ENTRY_CopyBytes2,           // MOV B0+rb
    /* B6 */ ENTRY_CopyBytes2,           // MOV B0+rb
    /* B7 */ ENTRY_CopyBytes2,           // MOV B0+rb
    /* B8 */ ENTRY_CopyBytes3Or5Rax,     // MOV B8+rb
    /* B9 */ ENTRY_CopyBytes3Or5Rax,     // MOV B8+rb
    /* BA */ ENTRY_CopyBytes3Or5Rax,     // MOV B8+rb
    /* BB */ ENTRY_CopyBytes3Or5Rax,     // MOV B8+rb
    /* BC */ ENTRY_CopyBytes3Or5Rax,     // MOV B8+rb
    /* BD */ ENTRY_CopyBytes3Or5Rax,     // MOV B8+rb
    /* BE */ ENTRY_CopyBytes3Or5Rax,     // MOV B8+rb
    /* BF */ ENTRY_CopyBytes3Or5Rax,     // MOV B8+rb
    /* C0 */ ENTRY_CopyBytes2Mod1,       // RCL/2 ib, etc.
    /* C1 */ ENTRY_CopyBytes2Mod1,       // RCL/2 ib, etc.
    /* C2 */ ENTRY_CopyBytes3,           // RET
    /* C3 */ ENTRY_CopyBytes1,           // RET
    /* C4 */ ENTRY_CopyVex3,             // LES, VEX 3-byte opcodes.
    /* C5 */ ENTRY_CopyVex2,             // LDS, VEX 2-byte opcodes.
    /* C6 */ ENTRY_CopyBytes2Mod1,       // MOV
    /* C7 */ ENTRY_CopyBytes2ModOperand, // MOV/0 XBEGIN/7
    /* C8 */ ENTRY_CopyBytes4,           // ENTER
    /* C9 */ ENTRY_CopyBytes1,           // LEAVE
    /* CA */ ENTRY_CopyBytes3Dynamic,    // RET
    /* CB */ ENTRY_CopyBytes1Dynamic,    // RET
    /* CC */ ENTRY_CopyBytes1Dynamic,    // INT 3
    /* CD */ ENTRY_CopyBytes2Dynamic,    // INT ib
#ifdef DETOURS_X64
    /* CE */ ENTRY_Invalid, // Invalid
#else
    /* CE */ ENTRY_CopyBytes1Dynamic, // INTO
#endif
    /* CF */ ENTRY_CopyBytes1Dynamic, // IRET
    /* D0 */ ENTRY_CopyBytes2Mod,     // RCL/2, etc.
    /* D1 */ ENTRY_CopyBytes2Mod,     // RCL/2, etc.
    /* D2 */ ENTRY_CopyBytes2Mod,     // RCL/2, etc.
    /* D3 */ ENTRY_CopyBytes2Mod,     // RCL/2, etc.
#ifdef DETOURS_X64
    /* D4 */ ENTRY_Invalid, // Invalid
    /* D5 */ ENTRY_Invalid, // Invalid
#else
    /* D4 */ ENTRY_CopyBytes2, // AAM
    /* D5 */ ENTRY_CopyBytes2, // AAD
#endif
    /* D6 */ ENTRY_Invalid,             // Invalid
    /* D7 */ ENTRY_CopyBytes1,          // XLAT/XLATB
    /* D8 */ ENTRY_CopyBytes2Mod,       // FADD, etc.
    /* D9 */ ENTRY_CopyBytes2Mod,       // F2XM1, etc.
    /* DA */ ENTRY_CopyBytes2Mod,       // FLADD, etc.
    /* DB */ ENTRY_CopyBytes2Mod,       // FCLEX, etc.
    /* DC */ ENTRY_CopyBytes2Mod,       // FADD/0, etc.
    /* DD */ ENTRY_CopyBytes2Mod,       // FFREE, etc.
    /* DE */ ENTRY_CopyBytes2Mod,       // FADDP, etc.
    /* DF */ ENTRY_CopyBytes2Mod,       // FBLD/4, etc.
    /* E0 */ ENTRY_CopyBytes2CantJump,  // LOOPNE cb
    /* E1 */ ENTRY_CopyBytes2CantJump,  // LOOPE cb
    /* E2 */ ENTRY_CopyBytes2CantJump,  // LOOP cb
    /* E3 */ ENTRY_CopyBytes2CantJump,  // JCXZ/JECXZ
    /* E4 */ ENTRY_CopyBytes2,          // IN ib
    /* E5 */ ENTRY_CopyBytes2,          // IN id
    /* E6 */ ENTRY_CopyBytes2,          // OUT ib
    /* E7 */ ENTRY_CopyBytes2,          // OUT ib
    /* E8 */ ENTRY_CopyBytes3Or5Target, // CALL cd
    /* E9 */ ENTRY_CopyBytes3Or5Target, // JMP cd
#ifdef DETOURS_X64
    /* EA */ ENTRY_Invalid, // Invalid
#else
    /* EA */ ENTRY_CopyBytes5Or7Dynamic, // JMP cp
#endif
    /* EB */ ENTRY_CopyBytes2Jump,    // JMP cb
    /* EC */ ENTRY_CopyBytes1,        // IN ib
    /* ED */ ENTRY_CopyBytes1,        // IN id
    /* EE */ ENTRY_CopyBytes1,        // OUT
    /* EF */ ENTRY_CopyBytes1,        // OUT
    /* F0 */ ENTRY_CopyBytesPrefix,   // LOCK prefix
    /* F1 */ ENTRY_CopyBytes1Dynamic, // INT1 / ICEBP somewhat documented by AMD, not by Intel
    /* F2 */ ENTRY_CopyF2,            // REPNE prefix
                                      //#ifdef DETOURS_X86
    /* F3 */ ENTRY_CopyF3,            // REPE prefix
                                      //#else
                                      // This does presently suffice for AMD64 but it requires tracing
                                      // through a bunch of code to verify and seems not worth maintaining.
                                      //  /* F3 */ ENTRY_CopyBytesPrefix,                    // REPE prefix
                                      //#endif
    /* F4 */ ENTRY_CopyBytes1,        // HLT
    /* F5 */ ENTRY_CopyBytes1,        // CMC
    /* F6 */ ENTRY_CopyF6,            // TEST/0, DIV/6
    /* F7 */ ENTRY_CopyF7,            // TEST/0, DIV/6
    /* F8 */ ENTRY_CopyBytes1,        // CLC
    /* F9 */ ENTRY_CopyBytes1,        // STC
    /* FA */ ENTRY_CopyBytes1,        // CLI
    /* FB */ ENTRY_CopyBytes1,        // STI
    /* FC */ ENTRY_CopyBytes1,        // CLD
    /* FD */ ENTRY_CopyBytes1,        // STD
    /* FE */ ENTRY_CopyBytes2Mod,     // DEC/1,INC/0
    /* FF */ ENTRY_CopyFF,            // CALL/2
};

const CDetourDis::COPYENTRY CDetourDis::s_rceCopyTable0F[] = {
#ifdef DETOURS_X86
    /* 00 */ ENTRY_Copy0F00, // sldt/0 str/1 lldt/2 ltr/3 err/4 verw/5 jmpe/6/dynamic invalid/7
#else
    /* 00 */ ENTRY_CopyBytes2Mod, // sldt/0 str/1 lldt/2 ltr/3 err/4 verw/5 jmpe/6/dynamic invalid/7
#endif
    /* 01 */ ENTRY_CopyBytes2Mod,  // INVLPG/7, etc.
    /* 02 */ ENTRY_CopyBytes2Mod,  // LAR/r
    /* 03 */ ENTRY_CopyBytes2Mod,  // LSL/r
    /* 04 */ ENTRY_Invalid,        // _04
    /* 05 */ ENTRY_CopyBytes1,     // SYSCALL
    /* 06 */ ENTRY_CopyBytes1,     // CLTS
    /* 07 */ ENTRY_CopyBytes1,     // SYSRET
    /* 08 */ ENTRY_CopyBytes1,     // INVD
    /* 09 */ ENTRY_CopyBytes1,     // WBINVD
    /* 0A */ ENTRY_Invalid,        // _0A
    /* 0B */ ENTRY_CopyBytes1,     // UD2
    /* 0C */ ENTRY_Invalid,        // _0C
    /* 0D */ ENTRY_CopyBytes2Mod,  // PREFETCH
    /* 0E */ ENTRY_CopyBytes1,     // FEMMS (3DNow -- not in Intel documentation)
    /* 0F */ ENTRY_CopyBytes2Mod1, // 3DNow Opcodes
    /* 10 */ ENTRY_CopyBytes2Mod,  // MOVSS MOVUPD MOVSD
    /* 11 */ ENTRY_CopyBytes2Mod,  // MOVSS MOVUPD MOVSD
    /* 12 */ ENTRY_CopyBytes2Mod,  // MOVLPD
    /* 13 */ ENTRY_CopyBytes2Mod,  // MOVLPD
    /* 14 */ ENTRY_CopyBytes2Mod,  // UNPCKLPD
    /* 15 */ ENTRY_CopyBytes2Mod,  // UNPCKHPD
    /* 16 */ ENTRY_CopyBytes2Mod,  // MOVHPD
    /* 17 */ ENTRY_CopyBytes2Mod,  // MOVHPD
    /* 18 */ ENTRY_CopyBytes2Mod,  // PREFETCHINTA...
    /* 19 */ ENTRY_CopyBytes2Mod,  // NOP/r multi byte nop, not documented by Intel, documented by AMD
    /* 1A */ ENTRY_CopyBytes2Mod,  // NOP/r multi byte nop, not documented by Intel, documented by AMD
    /* 1B */ ENTRY_CopyBytes2Mod,  // NOP/r multi byte nop, not documented by Intel, documented by AMD
    /* 1C */ ENTRY_CopyBytes2Mod,  // NOP/r multi byte nop, not documented by Intel, documented by AMD
    /* 1D */ ENTRY_CopyBytes2Mod,  // NOP/r multi byte nop, not documented by Intel, documented by AMD
    /* 1E */ ENTRY_CopyBytes2Mod,  // NOP/r multi byte nop, not documented by Intel, documented by AMD
    /* 1F */ ENTRY_CopyBytes2Mod,  // NOP/r multi byte nop
    /* 20 */ ENTRY_CopyBytes2Mod,  // MOV/r
    /* 21 */ ENTRY_CopyBytes2Mod,  // MOV/r
    /* 22 */ ENTRY_CopyBytes2Mod,  // MOV/r
    /* 23 */ ENTRY_CopyBytes2Mod,  // MOV/r
#ifdef DETOURS_X64
    /* 24 */ ENTRY_Invalid, // _24
#else
    /* 24 */ ENTRY_CopyBytes2Mod, // MOV/r,TR TR is test register on 80386 and 80486, removed in Pentium
#endif
    /* 25 */ ENTRY_Invalid, // _25
#ifdef DETOURS_X64
    /* 26 */ ENTRY_Invalid, // _26
#else
    /* 26 */ ENTRY_CopyBytes2Mod, // MOV TR/r TR is test register on 80386 and 80486, removed in Pentium
#endif
    /* 27 */ ENTRY_Invalid,        // _27
    /* 28 */ ENTRY_CopyBytes2Mod,  // MOVAPS MOVAPD
    /* 29 */ ENTRY_CopyBytes2Mod,  // MOVAPS MOVAPD
    /* 2A */ ENTRY_CopyBytes2Mod,  // CVPI2PS &
    /* 2B */ ENTRY_CopyBytes2Mod,  // MOVNTPS MOVNTPD
    /* 2C */ ENTRY_CopyBytes2Mod,  // CVTTPS2PI &
    /* 2D */ ENTRY_CopyBytes2Mod,  // CVTPS2PI &
    /* 2E */ ENTRY_CopyBytes2Mod,  // UCOMISS UCOMISD
    /* 2F */ ENTRY_CopyBytes2Mod,  // COMISS COMISD
    /* 30 */ ENTRY_CopyBytes1,     // WRMSR
    /* 31 */ ENTRY_CopyBytes1,     // RDTSC
    /* 32 */ ENTRY_CopyBytes1,     // RDMSR
    /* 33 */ ENTRY_CopyBytes1,     // RDPMC
    /* 34 */ ENTRY_CopyBytes1,     // SYSENTER
    /* 35 */ ENTRY_CopyBytes1,     // SYSEXIT
    /* 36 */ ENTRY_Invalid,        // _36
    /* 37 */ ENTRY_CopyBytes1,     // GETSEC
    /* 38 */ ENTRY_CopyBytes3Mod,  // SSE3 Opcodes
    /* 39 */ ENTRY_Invalid,        // _39
    /* 3A */ ENTRY_CopyBytes3Mod1, // SSE3 Opcodes
    /* 3B */ ENTRY_Invalid,        // _3B
    /* 3C */ ENTRY_Invalid,        // _3C
    /* 3D */ ENTRY_Invalid,        // _3D
    /* 3E */ ENTRY_Invalid,        // _3E
    /* 3F */ ENTRY_Invalid,        // _3F
    /* 40 */ ENTRY_CopyBytes2Mod,  // CMOVO (0F 40)
    /* 41 */ ENTRY_CopyBytes2Mod,  // CMOVNO (0F 41)
    /* 42 */ ENTRY_CopyBytes2Mod,  // CMOVB & CMOVNE (0F 42)
    /* 43 */ ENTRY_CopyBytes2Mod,  // CMOVAE & CMOVNB (0F 43)
    /* 44 */ ENTRY_CopyBytes2Mod,  // CMOVE & CMOVZ (0F 44)
    /* 45 */ ENTRY_CopyBytes2Mod,  // CMOVNE & CMOVNZ (0F 45)
    /* 46 */ ENTRY_CopyBytes2Mod,  // CMOVBE & CMOVNA (0F 46)
    /* 47 */ ENTRY_CopyBytes2Mod,  // CMOVA & CMOVNBE (0F 47)
    /* 48 */ ENTRY_CopyBytes2Mod,  // CMOVS (0F 48)
    /* 49 */ ENTRY_CopyBytes2Mod,  // CMOVNS (0F 49)
    /* 4A */ ENTRY_CopyBytes2Mod,  // CMOVP & CMOVPE (0F 4A)
    /* 4B */ ENTRY_CopyBytes2Mod,  // CMOVNP & CMOVPO (0F 4B)
    /* 4C */ ENTRY_CopyBytes2Mod,  // CMOVL & CMOVNGE (0F 4C)
    /* 4D */ ENTRY_CopyBytes2Mod,  // CMOVGE & CMOVNL (0F 4D)
    /* 4E */ ENTRY_CopyBytes2Mod,  // CMOVLE & CMOVNG (0F 4E)
    /* 4F */ ENTRY_CopyBytes2Mod,  // CMOVG & CMOVNLE (0F 4F)
    /* 50 */ ENTRY_CopyBytes2Mod,  // MOVMSKPD MOVMSKPD
    /* 51 */ ENTRY_CopyBytes2Mod,  // SQRTPS &
    /* 52 */ ENTRY_CopyBytes2Mod,  // RSQRTTS RSQRTPS
    /* 53 */ ENTRY_CopyBytes2Mod,  // RCPPS RCPSS
    /* 54 */ ENTRY_CopyBytes2Mod,  // ANDPS ANDPD
    /* 55 */ ENTRY_CopyBytes2Mod,  // ANDNPS ANDNPD
    /* 56 */ ENTRY_CopyBytes2Mod,  // ORPS ORPD
    /* 57 */ ENTRY_CopyBytes2Mod,  // XORPS XORPD
    /* 58 */ ENTRY_CopyBytes2Mod,  // ADDPS &
    /* 59 */ ENTRY_CopyBytes2Mod,  // MULPS &
    /* 5A */ ENTRY_CopyBytes2Mod,  // CVTPS2PD &
    /* 5B */ ENTRY_CopyBytes2Mod,  // CVTDQ2PS &
    /* 5C */ ENTRY_CopyBytes2Mod,  // SUBPS &
    /* 5D */ ENTRY_CopyBytes2Mod,  // MINPS &
    /* 5E */ ENTRY_CopyBytes2Mod,  // DIVPS &
    /* 5F */ ENTRY_CopyBytes2Mod,  // MASPS &
    /* 60 */ ENTRY_CopyBytes2Mod,  // PUNPCKLBW/r
    /* 61 */ ENTRY_CopyBytes2Mod,  // PUNPCKLWD/r
    /* 62 */ ENTRY_CopyBytes2Mod,  // PUNPCKLWD/r
    /* 63 */ ENTRY_CopyBytes2Mod,  // PACKSSWB/r
    /* 64 */ ENTRY_CopyBytes2Mod,  // PCMPGTB/r
    /* 65 */ ENTRY_CopyBytes2Mod,  // PCMPGTW/r
    /* 66 */ ENTRY_CopyBytes2Mod,  // PCMPGTD/r
    /* 67 */ ENTRY_CopyBytes2Mod,  // PACKUSWB/r
    /* 68 */ ENTRY_CopyBytes2Mod,  // PUNPCKHBW/r
    /* 69 */ ENTRY_CopyBytes2Mod,  // PUNPCKHWD/r
    /* 6A */ ENTRY_CopyBytes2Mod,  // PUNPCKHDQ/r
    /* 6B */ ENTRY_CopyBytes2Mod,  // PACKSSDW/r
    /* 6C */ ENTRY_CopyBytes2Mod,  // PUNPCKLQDQ
    /* 6D */ ENTRY_CopyBytes2Mod,  // PUNPCKHQDQ
    /* 6E */ ENTRY_CopyBytes2Mod,  // MOVD/r
    /* 6F */ ENTRY_CopyBytes2Mod,  // MOV/r
    /* 70 */ ENTRY_CopyBytes2Mod1, // PSHUFW/r ib
    /* 71 */ ENTRY_CopyBytes2Mod1, // PSLLW/6 ib,PSRAW/4 ib,PSRLW/2 ib
    /* 72 */ ENTRY_CopyBytes2Mod1, // PSLLD/6 ib,PSRAD/4 ib,PSRLD/2 ib
    /* 73 */ ENTRY_CopyBytes2Mod1, // PSLLQ/6 ib,PSRLQ/2 ib
    /* 74 */ ENTRY_CopyBytes2Mod,  // PCMPEQB/r
    /* 75 */ ENTRY_CopyBytes2Mod,  // PCMPEQW/r
    /* 76 */ ENTRY_CopyBytes2Mod,  // PCMPEQD/r
    /* 77 */ ENTRY_CopyBytes1,     // EMMS
                                   // extrq/insertq require mode=3 and are followed by two immediate bytes
    /* 78 */ ENTRY_Copy0F78,       // VMREAD/r, 66/EXTRQ/r/ib/ib, F2/INSERTQ/r/ib/ib
                                   // extrq/insertq require mod=3, therefore ENTRY_CopyBytes2, but it ends up the same
    /* 79 */ ENTRY_CopyBytes2Mod,  // VMWRITE/r, 66/EXTRQ/r, F2/INSERTQ/r
    /* 7A */ ENTRY_Invalid,        // _7A
    /* 7B */ ENTRY_Invalid,        // _7B
    /* 7C */ ENTRY_CopyBytes2Mod,  // HADDPS
    /* 7D */ ENTRY_CopyBytes2Mod,  // HSUBPS
    /* 7E */ ENTRY_CopyBytes2Mod,  // MOVD/r
    /* 7F */ ENTRY_CopyBytes2Mod,  // MOV/r
    /* 80 */ ENTRY_CopyBytes3Or5Target, // JO
    /* 81 */ ENTRY_CopyBytes3Or5Target, // JNO
    /* 82 */ ENTRY_CopyBytes3Or5Target, // JB,JC,JNAE
    /* 83 */ ENTRY_CopyBytes3Or5Target, // JAE,JNB,JNC
    /* 84 */ ENTRY_CopyBytes3Or5Target, // JE,JZ,JZ
    /* 85 */ ENTRY_CopyBytes3Or5Target, // JNE,JNZ
    /* 86 */ ENTRY_CopyBytes3Or5Target, // JBE,JNA
    /* 87 */ ENTRY_CopyBytes3Or5Target, // JA,JNBE
    /* 88 */ ENTRY_CopyBytes3Or5Target, // JS
    /* 89 */ ENTRY_CopyBytes3Or5Target, // JNS
    /* 8A */ ENTRY_CopyBytes3Or5Target, // JP,JPE
    /* 8B */ ENTRY_CopyBytes3Or5Target, // JNP,JPO
    /* 8C */ ENTRY_CopyBytes3Or5Target, // JL,NGE
    /* 8D */ ENTRY_CopyBytes3Or5Target, // JGE,JNL
    /* 8E */ ENTRY_CopyBytes3Or5Target, // JLE,JNG
    /* 8F */ ENTRY_CopyBytes3Or5Target, // JG,JNLE
    /* 90 */ ENTRY_CopyBytes2Mod,       // CMOVO (0F 40)
    /* 91 */ ENTRY_CopyBytes2Mod,       // CMOVNO (0F 41)
    /* 92 */ ENTRY_CopyBytes2Mod,       // CMOVB & CMOVC & CMOVNAE (0F 42)
    /* 93 */ ENTRY_CopyBytes2Mod,       // CMOVAE & CMOVNB & CMOVNC (0F 43)
    /* 94 */ ENTRY_CopyBytes2Mod,       // CMOVE & CMOVZ (0F 44)
    /* 95 */ ENTRY_CopyBytes2Mod,       // CMOVNE & CMOVNZ (0F 45)
    /* 96 */ ENTRY_CopyBytes2Mod,       // CMOVBE & CMOVNA (0F 46)
    /* 97 */ ENTRY_CopyBytes2Mod,       // CMOVA & CMOVNBE (0F 47)
    /* 98 */ ENTRY_CopyBytes2Mod,       // CMOVS (0F 48)
    /* 99 */ ENTRY_CopyBytes2Mod,       // CMOVNS (0F 49)
    /* 9A */ ENTRY_CopyBytes2Mod,       // CMOVP & CMOVPE (0F 4A)
    /* 9B */ ENTRY_CopyBytes2Mod,       // CMOVNP & CMOVPO (0F 4B)
    /* 9C */ ENTRY_CopyBytes2Mod,       // CMOVL & CMOVNGE (0F 4C)
    /* 9D */ ENTRY_CopyBytes2Mod,       // CMOVGE & CMOVNL (0F 4D)
    /* 9E */ ENTRY_CopyBytes2Mod,       // CMOVLE & CMOVNG (0F 4E)
    /* 9F */ ENTRY_CopyBytes2Mod,       // CMOVG & CMOVNLE (0F 4F)
    /* A0 */ ENTRY_CopyBytes1,          // PUSH
    /* A1 */ ENTRY_CopyBytes1,          // POP
    /* A2 */ ENTRY_CopyBytes1,          // CPUID
    /* A3 */ ENTRY_CopyBytes2Mod,       // BT  (0F A3)
    /* A4 */ ENTRY_CopyBytes2Mod1,      // SHLD
    /* A5 */ ENTRY_CopyBytes2Mod,       // SHLD
    /* A6 */ ENTRY_CopyBytes2Mod,       // XBTS
    /* A7 */ ENTRY_CopyBytes2Mod,       // IBTS
    /* A8 */ ENTRY_CopyBytes1,          // PUSH
    /* A9 */ ENTRY_CopyBytes1,          // POP
    /* AA */ ENTRY_CopyBytes1,          // RSM
    /* AB */ ENTRY_CopyBytes2Mod,       // BTS (0F AB)
    /* AC */ ENTRY_CopyBytes2Mod1,      // SHRD
    /* AD */ ENTRY_CopyBytes2Mod,       // SHRD

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
    /* AE */
    ENTRY_CopyBytes2Mod, // fxsave fxrstor ldmxcsr stmxcsr xsave xrstor saveopt clflush lfence mfence sfence rdfsbase rdgsbase wrfsbase wrgsbase
    /* AF */ ENTRY_CopyBytes2Mod, // IMUL (0F AF)
    /* B0 */ ENTRY_CopyBytes2Mod, // CMPXCHG (0F B0)
    /* B1 */ ENTRY_CopyBytes2Mod, // CMPXCHG (0F B1)
    /* B2 */ ENTRY_CopyBytes2Mod, // LSS/r
    /* B3 */ ENTRY_CopyBytes2Mod, // BTR (0F B3)
    /* B4 */ ENTRY_CopyBytes2Mod, // LFS/r
    /* B5 */ ENTRY_CopyBytes2Mod, // LGS/r
    /* B6 */ ENTRY_CopyBytes2Mod, // MOVZX/r
    /* B7 */ ENTRY_CopyBytes2Mod, // MOVZX/r
#ifdef DETOURS_X86
    /* B8 */ ENTRY_Copy0FB8, // jmpe f3/popcnt
#else
    /* B8 */ ENTRY_CopyBytes2Mod, // f3/popcnt
#endif
    /* B9 */ ENTRY_Invalid,        // _B9
    /* BA */ ENTRY_CopyBytes2Mod1, // BT & BTC & BTR & BTS (0F BA)
    /* BB */ ENTRY_CopyBytes2Mod,  // BTC (0F BB)
    /* BC */ ENTRY_CopyBytes2Mod,  // BSF (0F BC)
    /* BD */ ENTRY_CopyBytes2Mod,  // BSR (0F BD)
    /* BE */ ENTRY_CopyBytes2Mod,  // MOVSX/r
    /* BF */ ENTRY_CopyBytes2Mod,  // MOVSX/r
    /* C0 */ ENTRY_CopyBytes2Mod,  // XADD/r
    /* C1 */ ENTRY_CopyBytes2Mod,  // XADD/r
    /* C2 */ ENTRY_CopyBytes2Mod1, // CMPPS &
    /* C3 */ ENTRY_CopyBytes2Mod,  // MOVNTI
    /* C4 */ ENTRY_CopyBytes2Mod1, // PINSRW /r ib
    /* C5 */ ENTRY_CopyBytes2Mod1, // PEXTRW /r ib
    /* C6 */ ENTRY_CopyBytes2Mod1, // SHUFPS & SHUFPD
    /* C7 */ ENTRY_CopyBytes2Mod,  // CMPXCHG8B (0F C7)
    /* C8 */ ENTRY_CopyBytes1,     // BSWAP 0F C8 + rd
    /* C9 */ ENTRY_CopyBytes1,     // BSWAP 0F C8 + rd
    /* CA */ ENTRY_CopyBytes1,     // BSWAP 0F C8 + rd
    /* CB */ ENTRY_CopyBytes1,     // CVTPD2PI BSWAP 0F C8 + rd
    /* CC */ ENTRY_CopyBytes1,     // BSWAP 0F C8 + rd
    /* CD */ ENTRY_CopyBytes1,     // BSWAP 0F C8 + rd
    /* CE */ ENTRY_CopyBytes1,     // BSWAP 0F C8 + rd
    /* CF */ ENTRY_CopyBytes1,     // BSWAP 0F C8 + rd
    /* D0 */ ENTRY_CopyBytes2Mod,  // ADDSUBPS (untestd)
    /* D1 */ ENTRY_CopyBytes2Mod,  // PSRLW/r
    /* D2 */ ENTRY_CopyBytes2Mod,  // PSRLD/r
    /* D3 */ ENTRY_CopyBytes2Mod,  // PSRLQ/r
    /* D4 */ ENTRY_CopyBytes2Mod,  // PADDQ
    /* D5 */ ENTRY_CopyBytes2Mod,  // PMULLW/r
    /* D6 */ ENTRY_CopyBytes2Mod,  // MOVDQ2Q / MOVQ2DQ
    /* D7 */ ENTRY_CopyBytes2Mod,  // PMOVMSKB/r
    /* D8 */ ENTRY_CopyBytes2Mod,  // PSUBUSB/r
    /* D9 */ ENTRY_CopyBytes2Mod,  // PSUBUSW/r
    /* DA */ ENTRY_CopyBytes2Mod,  // PMINUB/r
    /* DB */ ENTRY_CopyBytes2Mod,  // PAND/r
    /* DC */ ENTRY_CopyBytes2Mod,  // PADDUSB/r
    /* DD */ ENTRY_CopyBytes2Mod,  // PADDUSW/r
    /* DE */ ENTRY_CopyBytes2Mod,  // PMAXUB/r
    /* DF */ ENTRY_CopyBytes2Mod,  // PANDN/r
    /* E0 */ ENTRY_CopyBytes2Mod,  // PAVGB
    /* E1 */ ENTRY_CopyBytes2Mod,  // PSRAW/r
    /* E2 */ ENTRY_CopyBytes2Mod,  // PSRAD/r
    /* E3 */ ENTRY_CopyBytes2Mod,  // PAVGW
    /* E4 */ ENTRY_CopyBytes2Mod,  // PMULHUW/r
    /* E5 */ ENTRY_CopyBytes2Mod,  // PMULHW/r
    /* E6 */ ENTRY_CopyBytes2Mod,  // CTDQ2PD &
    /* E7 */ ENTRY_CopyBytes2Mod,  // MOVNTQ
    /* E8 */ ENTRY_CopyBytes2Mod,  // PSUBB/r
    /* E9 */ ENTRY_CopyBytes2Mod,  // PSUBW/r
    /* EA */ ENTRY_CopyBytes2Mod,  // PMINSW/r
    /* EB */ ENTRY_CopyBytes2Mod,  // POR/r
    /* EC */ ENTRY_CopyBytes2Mod,  // PADDSB/r
    /* ED */ ENTRY_CopyBytes2Mod,  // PADDSW/r
    /* EE */ ENTRY_CopyBytes2Mod,  // PMAXSW /r
    /* EF */ ENTRY_CopyBytes2Mod,  // PXOR/r
    /* F0 */ ENTRY_CopyBytes2Mod,  // LDDQU
    /* F1 */ ENTRY_CopyBytes2Mod,  // PSLLW/r
    /* F2 */ ENTRY_CopyBytes2Mod,  // PSLLD/r
    /* F3 */ ENTRY_CopyBytes2Mod,  // PSLLQ/r
    /* F4 */ ENTRY_CopyBytes2Mod,  // PMULUDQ/r
    /* F5 */ ENTRY_CopyBytes2Mod,  // PMADDWD/r
    /* F6 */ ENTRY_CopyBytes2Mod,  // PSADBW/r
    /* F7 */ ENTRY_CopyBytes2Mod,  // MASKMOVQ
    /* F8 */ ENTRY_CopyBytes2Mod,  // PSUBB/r
    /* F9 */ ENTRY_CopyBytes2Mod,  // PSUBW/r
    /* FA */ ENTRY_CopyBytes2Mod,  // PSUBD/r
    /* FB */ ENTRY_CopyBytes2Mod,  // FSUBQ/r
    /* FC */ ENTRY_CopyBytes2Mod,  // PADDB/r
    /* FD */ ENTRY_CopyBytes2Mod,  // PADDW/r
    /* FE */ ENTRY_CopyBytes2Mod,  // PADDD/r
    /* FF */ ENTRY_Invalid,        // _FF
};
#endif // defined(DETOURS_X64) || defined(DETOURS_X86)
