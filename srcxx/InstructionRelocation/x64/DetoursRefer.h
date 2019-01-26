
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
  ULONG nOpcode : 8;      // Opcode (ignored)
  ULONG nFixedSize : 4;   // Fixed size of opcode
  ULONG nFixedSize16 : 4; // Fixed size when 16 bit operand
  ULONG nModOffset : 4;   // Offset to mod/rm byte (0=none)
  ULONG nRelOffset : 4;   // Offset to relative target.
  ULONG nFlagBits : 4;    // Flags for DYNAMIC, etc.
  COPYFUNC pfCopy;        // Function pointer.
};

// clang-format off
const CDetourDis::COPYENTRY CDetourDis::s_rceCopyTable[257] =
{
    { 0x00, ENTRY_CopyBytes2Mod },                      // ADD /r
    { 0x01, ENTRY_CopyBytes2Mod },                      // ADD /r
    { 0x02, ENTRY_CopyBytes2Mod },                      // ADD /r
    { 0x03, ENTRY_CopyBytes2Mod },                      // ADD /r
    { 0x04, ENTRY_CopyBytes2 },                         // ADD ib
    { 0x05, ENTRY_CopyBytes3Or5 },                      // ADD iw
#ifdef DETOURS_X64
    { 0x06, ENTRY_Invalid },                            // Invalid
    { 0x07, ENTRY_Invalid },                            // Invalid
#else
    { 0x06, ENTRY_CopyBytes1 },                         // PUSH
    { 0x07, ENTRY_CopyBytes1 },                         // POP
#endif
    { 0x08, ENTRY_CopyBytes2Mod },                      // OR /r
    { 0x09, ENTRY_CopyBytes2Mod },                      // OR /r
    { 0x0A, ENTRY_CopyBytes2Mod },                      // OR /r
    { 0x0B, ENTRY_CopyBytes2Mod },                      // OR /r
    { 0x0C, ENTRY_CopyBytes2 },                         // OR ib
    { 0x0D, ENTRY_CopyBytes3Or5 },                      // OR iw
#ifdef DETOURS_X64
    { 0x0E, ENTRY_Invalid },                            // Invalid
#else
    { 0x0E, ENTRY_CopyBytes1 },                         // PUSH
#endif
    { 0x0F, ENTRY_Copy0F },                             // Extension Ops
    { 0x10, ENTRY_CopyBytes2Mod },                      // ADC /r
    { 0x11, ENTRY_CopyBytes2Mod },                      // ADC /r
    { 0x12, ENTRY_CopyBytes2Mod },                      // ADC /r
    { 0x13, ENTRY_CopyBytes2Mod },                      // ADC /r
    { 0x14, ENTRY_CopyBytes2 },                         // ADC ib
    { 0x15, ENTRY_CopyBytes3Or5 },                      // ADC id
#ifdef DETOURS_X64
    { 0x16, ENTRY_Invalid },                            // Invalid
    { 0x17, ENTRY_Invalid },                            // Invalid
#else
    { 0x16, ENTRY_CopyBytes1 },                         // PUSH
    { 0x17, ENTRY_CopyBytes1 },                         // POP
#endif
    { 0x18, ENTRY_CopyBytes2Mod },                      // SBB /r
    { 0x19, ENTRY_CopyBytes2Mod },                      // SBB /r
    { 0x1A, ENTRY_CopyBytes2Mod },                      // SBB /r
    { 0x1B, ENTRY_CopyBytes2Mod },                      // SBB /r
    { 0x1C, ENTRY_CopyBytes2 },                         // SBB ib
    { 0x1D, ENTRY_CopyBytes3Or5 },                      // SBB id
#ifdef DETOURS_X64
    { 0x1E, ENTRY_Invalid },                            // Invalid
    { 0x1F, ENTRY_Invalid },                            // Invalid
#else
    { 0x1E, ENTRY_CopyBytes1 },                         // PUSH
    { 0x1F, ENTRY_CopyBytes1 },                         // POP
#endif
    { 0x20, ENTRY_CopyBytes2Mod },                      // AND /r
    { 0x21, ENTRY_CopyBytes2Mod },                      // AND /r
    { 0x22, ENTRY_CopyBytes2Mod },                      // AND /r
    { 0x23, ENTRY_CopyBytes2Mod },                      // AND /r
    { 0x24, ENTRY_CopyBytes2 },                         // AND ib
    { 0x25, ENTRY_CopyBytes3Or5 },                      // AND id
    { 0x26, ENTRY_CopyBytesSegment },                   // ES prefix
#ifdef DETOURS_X64
    { 0x27, ENTRY_Invalid },                            // Invalid
#else
    { 0x27, ENTRY_CopyBytes1 },                         // DAA
#endif
    { 0x28, ENTRY_CopyBytes2Mod },                      // SUB /r
    { 0x29, ENTRY_CopyBytes2Mod },                      // SUB /r
    { 0x2A, ENTRY_CopyBytes2Mod },                      // SUB /r
    { 0x2B, ENTRY_CopyBytes2Mod },                      // SUB /r
    { 0x2C, ENTRY_CopyBytes2 },                         // SUB ib
    { 0x2D, ENTRY_CopyBytes3Or5 },                      // SUB id
    { 0x2E, ENTRY_CopyBytesSegment },                   // CS prefix
#ifdef DETOURS_X64
    { 0x2F, ENTRY_Invalid },                            // Invalid
#else
    { 0x2F, ENTRY_CopyBytes1 },                         // DAS
#endif
    { 0x30, ENTRY_CopyBytes2Mod },                      // XOR /r
    { 0x31, ENTRY_CopyBytes2Mod },                      // XOR /r
    { 0x32, ENTRY_CopyBytes2Mod },                      // XOR /r
    { 0x33, ENTRY_CopyBytes2Mod },                      // XOR /r
    { 0x34, ENTRY_CopyBytes2 },                         // XOR ib
    { 0x35, ENTRY_CopyBytes3Or5 },                      // XOR id
    { 0x36, ENTRY_CopyBytesSegment },                   // SS prefix
#ifdef DETOURS_X64
    { 0x37, ENTRY_Invalid },                            // Invalid
#else
    { 0x37, ENTRY_CopyBytes1 },                         // AAA
#endif
    { 0x38, ENTRY_CopyBytes2Mod },                      // CMP /r
    { 0x39, ENTRY_CopyBytes2Mod },                      // CMP /r
    { 0x3A, ENTRY_CopyBytes2Mod },                      // CMP /r
    { 0x3B, ENTRY_CopyBytes2Mod },                      // CMP /r
    { 0x3C, ENTRY_CopyBytes2 },                         // CMP ib
    { 0x3D, ENTRY_CopyBytes3Or5 },                      // CMP id
    { 0x3E, ENTRY_CopyBytesSegment },                   // DS prefix
#ifdef DETOURS_X64
    { 0x3F, ENTRY_Invalid },                            // Invalid
#else
    { 0x3F, ENTRY_CopyBytes1 },                         // AAS
#endif
#ifdef DETOURS_X64 // For Rax Prefix
    { 0x40, ENTRY_CopyBytesRax },                       // Rax
    { 0x41, ENTRY_CopyBytesRax },                       // Rax
    { 0x42, ENTRY_CopyBytesRax },                       // Rax
    { 0x43, ENTRY_CopyBytesRax },                       // Rax
    { 0x44, ENTRY_CopyBytesRax },                       // Rax
    { 0x45, ENTRY_CopyBytesRax },                       // Rax
    { 0x46, ENTRY_CopyBytesRax },                       // Rax
    { 0x47, ENTRY_CopyBytesRax },                       // Rax
    { 0x48, ENTRY_CopyBytesRax },                       // Rax
    { 0x49, ENTRY_CopyBytesRax },                       // Rax
    { 0x4A, ENTRY_CopyBytesRax },                       // Rax
    { 0x4B, ENTRY_CopyBytesRax },                       // Rax
    { 0x4C, ENTRY_CopyBytesRax },                       // Rax
    { 0x4D, ENTRY_CopyBytesRax },                       // Rax
    { 0x4E, ENTRY_CopyBytesRax },                       // Rax
    { 0x4F, ENTRY_CopyBytesRax },                       // Rax
#else
    { 0x40, ENTRY_CopyBytes1 },                         // INC
    { 0x41, ENTRY_CopyBytes1 },                         // INC
    { 0x42, ENTRY_CopyBytes1 },                         // INC
    { 0x43, ENTRY_CopyBytes1 },                         // INC
    { 0x44, ENTRY_CopyBytes1 },                         // INC
    { 0x45, ENTRY_CopyBytes1 },                         // INC
    { 0x46, ENTRY_CopyBytes1 },                         // INC
    { 0x47, ENTRY_CopyBytes1 },                         // INC
    { 0x48, ENTRY_CopyBytes1 },                         // DEC
    { 0x49, ENTRY_CopyBytes1 },                         // DEC
    { 0x4A, ENTRY_CopyBytes1 },                         // DEC
    { 0x4B, ENTRY_CopyBytes1 },                         // DEC
    { 0x4C, ENTRY_CopyBytes1 },                         // DEC
    { 0x4D, ENTRY_CopyBytes1 },                         // DEC
    { 0x4E, ENTRY_CopyBytes1 },                         // DEC
    { 0x4F, ENTRY_CopyBytes1 },                         // DEC
#endif
    { 0x50, ENTRY_CopyBytes1 },                         // PUSH
    { 0x51, ENTRY_CopyBytes1 },                         // PUSH
    { 0x52, ENTRY_CopyBytes1 },                         // PUSH
    { 0x53, ENTRY_CopyBytes1 },                         // PUSH
    { 0x54, ENTRY_CopyBytes1 },                         // PUSH
    { 0x55, ENTRY_CopyBytes1 },                         // PUSH
    { 0x56, ENTRY_CopyBytes1 },                         // PUSH
    { 0x57, ENTRY_CopyBytes1 },                         // PUSH
    { 0x58, ENTRY_CopyBytes1 },                         // POP
    { 0x59, ENTRY_CopyBytes1 },                         // POP
    { 0x5A, ENTRY_CopyBytes1 },                         // POP
    { 0x5B, ENTRY_CopyBytes1 },                         // POP
    { 0x5C, ENTRY_CopyBytes1 },                         // POP
    { 0x5D, ENTRY_CopyBytes1 },                         // POP
    { 0x5E, ENTRY_CopyBytes1 },                         // POP
    { 0x5F, ENTRY_CopyBytes1 },                         // POP
#ifdef DETOURS_X64
    { 0x60, ENTRY_Invalid },                            // Invalid
    { 0x61, ENTRY_Invalid },                            // Invalid
    { 0x62, ENTRY_Invalid },                            // Invalid (not yet implemented Intel EVEX support)
#else
    { 0x60, ENTRY_CopyBytes1 },                         // PUSHAD
    { 0x61, ENTRY_CopyBytes1 },                         // POPAD
    { 0x62, ENTRY_CopyBytes2Mod },                      // BOUND /r
#endif
    { 0x63, ENTRY_CopyBytes2Mod },                      // 32bit ARPL /r, 64bit MOVSXD
    { 0x64, ENTRY_CopyBytesSegment },                   // FS prefix
    { 0x65, ENTRY_CopyBytesSegment },                   // GS prefix
    { 0x66, ENTRY_Copy66 },                             // Operand Prefix
    { 0x67, ENTRY_Copy67 },                             // Address Prefix
    { 0x68, ENTRY_CopyBytes3Or5 },                      // PUSH
    { 0x69, ENTRY_CopyBytes2ModOperand },               // IMUL /r iz
    { 0x6A, ENTRY_CopyBytes2 },                         // PUSH
    { 0x6B, ENTRY_CopyBytes2Mod1 },                     // IMUL /r ib
    { 0x6C, ENTRY_CopyBytes1 },                         // INS
    { 0x6D, ENTRY_CopyBytes1 },                         // INS
    { 0x6E, ENTRY_CopyBytes1 },                         // OUTS/OUTSB
    { 0x6F, ENTRY_CopyBytes1 },                         // OUTS/OUTSW
    { 0x70, ENTRY_CopyBytes2Jump },                     // JO           // 0f80
    { 0x71, ENTRY_CopyBytes2Jump },                     // JNO          // 0f81
    { 0x72, ENTRY_CopyBytes2Jump },                     // JB/JC/JNAE   // 0f82
    { 0x73, ENTRY_CopyBytes2Jump },                     // JAE/JNB/JNC  // 0f83
    { 0x74, ENTRY_CopyBytes2Jump },                     // JE/JZ        // 0f84
    { 0x75, ENTRY_CopyBytes2Jump },                     // JNE/JNZ      // 0f85
    { 0x76, ENTRY_CopyBytes2Jump },                     // JBE/JNA      // 0f86
    { 0x77, ENTRY_CopyBytes2Jump },                     // JA/JNBE      // 0f87
    { 0x78, ENTRY_CopyBytes2Jump },                     // JS           // 0f88
    { 0x79, ENTRY_CopyBytes2Jump },                     // JNS          // 0f89
    { 0x7A, ENTRY_CopyBytes2Jump },                     // JP/JPE       // 0f8a
    { 0x7B, ENTRY_CopyBytes2Jump },                     // JNP/JPO      // 0f8b
    { 0x7C, ENTRY_CopyBytes2Jump },                     // JL/JNGE      // 0f8c
    { 0x7D, ENTRY_CopyBytes2Jump },                     // JGE/JNL      // 0f8d
    { 0x7E, ENTRY_CopyBytes2Jump },                     // JLE/JNG      // 0f8e
    { 0x7F, ENTRY_CopyBytes2Jump },                     // JG/JNLE      // 0f8f
    { 0x80, ENTRY_CopyBytes2Mod1 },                     // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 byte reg, immediate byte
    { 0x81, ENTRY_CopyBytes2ModOperand },               // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 byte reg, immediate word or dword
#ifdef DETOURS_X64
    { 0x82, ENTRY_Invalid },                            // Invalid
#else
    { 0x82, ENTRY_CopyBytes2Mod1 },                     // MOV al,x
#endif
    { 0x83, ENTRY_CopyBytes2Mod1 },                     // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 reg, immediate byte
    { 0x84, ENTRY_CopyBytes2Mod },                      // TEST /r
    { 0x85, ENTRY_CopyBytes2Mod },                      // TEST /r
    { 0x86, ENTRY_CopyBytes2Mod },                      // XCHG /r @todo
    { 0x87, ENTRY_CopyBytes2Mod },                      // XCHG /r @todo
    { 0x88, ENTRY_CopyBytes2Mod },                      // MOV /r
    { 0x89, ENTRY_CopyBytes2Mod },                      // MOV /r
    { 0x8A, ENTRY_CopyBytes2Mod },                      // MOV /r
    { 0x8B, ENTRY_CopyBytes2Mod },                      // MOV /r
    { 0x8C, ENTRY_CopyBytes2Mod },                      // MOV /r
    { 0x8D, ENTRY_CopyBytes2Mod },                      // LEA /r
    { 0x8E, ENTRY_CopyBytes2Mod },                      // MOV /r
    { 0x8F, ENTRY_CopyBytes2Mod },                      // POP /0
    { 0x90, ENTRY_CopyBytes1 },                         // NOP
    { 0x91, ENTRY_CopyBytes1 },                         // XCHG
    { 0x92, ENTRY_CopyBytes1 },                         // XCHG
    { 0x93, ENTRY_CopyBytes1 },                         // XCHG
    { 0x94, ENTRY_CopyBytes1 },                         // XCHG
    { 0x95, ENTRY_CopyBytes1 },                         // XCHG
    { 0x96, ENTRY_CopyBytes1 },                         // XCHG
    { 0x97, ENTRY_CopyBytes1 },                         // XCHG
    { 0x98, ENTRY_CopyBytes1 },                         // CWDE
    { 0x99, ENTRY_CopyBytes1 },                         // CDQ
#ifdef DETOURS_X64
    { 0x9A, ENTRY_Invalid },                            // Invalid
#else
    { 0x9A, ENTRY_CopyBytes5Or7Dynamic },               // CALL cp
#endif
    { 0x9B, ENTRY_CopyBytes1 },                         // WAIT/FWAIT
    { 0x9C, ENTRY_CopyBytes1 },                         // PUSHFD
    { 0x9D, ENTRY_CopyBytes1 },                         // POPFD
    { 0x9E, ENTRY_CopyBytes1 },                         // SAHF
    { 0x9F, ENTRY_CopyBytes1 },                         // LAHF
    { 0xA0, ENTRY_CopyBytes1Address },                  // MOV
    { 0xA1, ENTRY_CopyBytes1Address },                  // MOV
    { 0xA2, ENTRY_CopyBytes1Address },                  // MOV
    { 0xA3, ENTRY_CopyBytes1Address },                  // MOV
    { 0xA4, ENTRY_CopyBytes1 },                         // MOVS
    { 0xA5, ENTRY_CopyBytes1 },                         // MOVS/MOVSD
    { 0xA6, ENTRY_CopyBytes1 },                         // CMPS/CMPSB
    { 0xA7, ENTRY_CopyBytes1 },                         // CMPS/CMPSW
    { 0xA8, ENTRY_CopyBytes2 },                         // TEST
    { 0xA9, ENTRY_CopyBytes3Or5 },                      // TEST
    { 0xAA, ENTRY_CopyBytes1 },                         // STOS/STOSB
    { 0xAB, ENTRY_CopyBytes1 },                         // STOS/STOSW
    { 0xAC, ENTRY_CopyBytes1 },                         // LODS/LODSB
    { 0xAD, ENTRY_CopyBytes1 },                         // LODS/LODSW
    { 0xAE, ENTRY_CopyBytes1 },                         // SCAS/SCASB
    { 0xAF, ENTRY_CopyBytes1 },                         // SCAS/SCASD
    { 0xB0, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB1, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB2, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB3, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB4, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB5, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB6, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB7, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB8, ENTRY_CopyBytes3Or5Rax },                   // MOV B8+rb
    { 0xB9, ENTRY_CopyBytes3Or5Rax },                   // MOV B8+rb
    { 0xBA, ENTRY_CopyBytes3Or5Rax },                   // MOV B8+rb
    { 0xBB, ENTRY_CopyBytes3Or5Rax },                   // MOV B8+rb
    { 0xBC, ENTRY_CopyBytes3Or5Rax },                   // MOV B8+rb
    { 0xBD, ENTRY_CopyBytes3Or5Rax },                   // MOV B8+rb
    { 0xBE, ENTRY_CopyBytes3Or5Rax },                   // MOV B8+rb
    { 0xBF, ENTRY_CopyBytes3Or5Rax },                   // MOV B8+rb
    { 0xC0, ENTRY_CopyBytes2Mod1 },                     // RCL/2 ib, etc.
    { 0xC1, ENTRY_CopyBytes2Mod1 },                     // RCL/2 ib, etc.
    { 0xC2, ENTRY_CopyBytes3 },                         // RET
    { 0xC3, ENTRY_CopyBytes1 },                         // RET
    { 0xC4, ENTRY_CopyVex3 },                           // LES, VEX 3-byte opcodes.
    { 0xC5, ENTRY_CopyVex2 },                           // LDS, VEX 2-byte opcodes.
    { 0xC6, ENTRY_CopyBytes2Mod1 },                     // MOV
    { 0xC7, ENTRY_CopyBytes2ModOperand },               // MOV/0 XBEGIN/7
    { 0xC8, ENTRY_CopyBytes4 },                         // ENTER
    { 0xC9, ENTRY_CopyBytes1 },                         // LEAVE
    { 0xCA, ENTRY_CopyBytes3Dynamic },                  // RET
    { 0xCB, ENTRY_CopyBytes1Dynamic },                  // RET
    { 0xCC, ENTRY_CopyBytes1Dynamic },                  // INT 3
    { 0xCD, ENTRY_CopyBytes2Dynamic },                  // INT ib
#ifdef DETOURS_X64
    { 0xCE, ENTRY_Invalid },                            // Invalid
#else
    { 0xCE, ENTRY_CopyBytes1Dynamic },                  // INTO
#endif
    { 0xCF, ENTRY_CopyBytes1Dynamic },                  // IRET
    { 0xD0, ENTRY_CopyBytes2Mod },                      // RCL/2, etc.
    { 0xD1, ENTRY_CopyBytes2Mod },                      // RCL/2, etc.
    { 0xD2, ENTRY_CopyBytes2Mod },                      // RCL/2, etc.
    { 0xD3, ENTRY_CopyBytes2Mod },                      // RCL/2, etc.
#ifdef DETOURS_X64
    { 0xD4, ENTRY_Invalid },                            // Invalid
    { 0xD5, ENTRY_Invalid },                            // Invalid
#else
    { 0xD4, ENTRY_CopyBytes2 },                         // AAM
    { 0xD5, ENTRY_CopyBytes2 },                         // AAD
#endif
    { 0xD6, ENTRY_Invalid },                            // Invalid
    { 0xD7, ENTRY_CopyBytes1 },                         // XLAT/XLATB
    { 0xD8, ENTRY_CopyBytes2Mod },                      // FADD, etc.
    { 0xD9, ENTRY_CopyBytes2Mod },                      // F2XM1, etc.
    { 0xDA, ENTRY_CopyBytes2Mod },                      // FLADD, etc.
    { 0xDB, ENTRY_CopyBytes2Mod },                      // FCLEX, etc.
    { 0xDC, ENTRY_CopyBytes2Mod },                      // FADD/0, etc.
    { 0xDD, ENTRY_CopyBytes2Mod },                      // FFREE, etc.
    { 0xDE, ENTRY_CopyBytes2Mod },                      // FADDP, etc.
    { 0xDF, ENTRY_CopyBytes2Mod },                      // FBLD/4, etc.
    { 0xE0, ENTRY_CopyBytes2CantJump },                 // LOOPNE cb
    { 0xE1, ENTRY_CopyBytes2CantJump },                 // LOOPE cb
    { 0xE2, ENTRY_CopyBytes2CantJump },                 // LOOP cb
    { 0xE3, ENTRY_CopyBytes2CantJump },                 // JCXZ/JECXZ
    { 0xE4, ENTRY_CopyBytes2 },                         // IN ib
    { 0xE5, ENTRY_CopyBytes2 },                         // IN id
    { 0xE6, ENTRY_CopyBytes2 },                         // OUT ib
    { 0xE7, ENTRY_CopyBytes2 },                         // OUT ib
    { 0xE8, ENTRY_CopyBytes3Or5Target },                // CALL cd
    { 0xE9, ENTRY_CopyBytes3Or5Target },                // JMP cd
#ifdef DETOURS_X64
    { 0xEA, ENTRY_Invalid },                            // Invalid
#else
    { 0xEA, ENTRY_CopyBytes5Or7Dynamic },               // JMP cp
#endif
    { 0xEB, ENTRY_CopyBytes2Jump },                     // JMP cb
    { 0xEC, ENTRY_CopyBytes1 },                         // IN ib
    { 0xED, ENTRY_CopyBytes1 },                         // IN id
    { 0xEE, ENTRY_CopyBytes1 },                         // OUT
    { 0xEF, ENTRY_CopyBytes1 },                         // OUT
    { 0xF0, ENTRY_CopyBytesPrefix },                    // LOCK prefix
    { 0xF1, ENTRY_CopyBytes1Dynamic },                  // INT1 / ICEBP somewhat documented by AMD, not by Intel
    { 0xF2, ENTRY_CopyF2 },                             // REPNE prefix
//#ifdef DETOURS_X86
    { 0xF3, ENTRY_CopyF3 },                             // REPE prefix
//#else
// This does presently suffice for AMD64 but it requires tracing
// through a bunch of code to verify and seems not worth maintaining.
//  { 0xF3, ENTRY_CopyBytesPrefix },                    // REPE prefix
//#endif
    { 0xF4, ENTRY_CopyBytes1 },                         // HLT
    { 0xF5, ENTRY_CopyBytes1 },                         // CMC
    { 0xF6, ENTRY_CopyF6 },                             // TEST/0, DIV/6
    { 0xF7, ENTRY_CopyF7 },                             // TEST/0, DIV/6
    { 0xF8, ENTRY_CopyBytes1 },                         // CLC
    { 0xF9, ENTRY_CopyBytes1 },                         // STC
    { 0xFA, ENTRY_CopyBytes1 },                         // CLI
    { 0xFB, ENTRY_CopyBytes1 },                         // STI
    { 0xFC, ENTRY_CopyBytes1 },                         // CLD
    { 0xFD, ENTRY_CopyBytes1 },                         // STD
    { 0xFE, ENTRY_CopyBytes2Mod },                      // DEC/1,INC/0
    { 0xFF, ENTRY_CopyFF },                             // CALL/2
    { 0, ENTRY_End },
};
// clang-format on
