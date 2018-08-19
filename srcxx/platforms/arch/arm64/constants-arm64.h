#ifndef ARCH_ARM64_CONSTANTS
#define ARCH_ARM64_CONSTANTS

#define LFT(a, b) (a << b)
#define RHT(a, b) (a >> b)

enum Bits {
  B0  = (1 << 0),
  B1  = (1 << 1),
  B2  = (1 << 2),
  B3  = (1 << 3),
  B4  = (1 << 4),
  B5  = (1 << 5),
  B6  = (1 << 6),
  B7  = (1 << 7),
  B8  = (1 << 8),
  B9  = (1 << 9),
  B10 = (1 << 10),
  B11 = (1 << 11),
  B12 = (1 << 12),
  B13 = (1 << 13),
  B14 = (1 << 14),
  B15 = (1 << 15),
  B16 = (1 << 16),
  B17 = (1 << 17),
  B18 = (1 << 18),
  B19 = (1 << 19),
  B20 = (1 << 20),
  B21 = (1 << 21),
  B22 = (1 << 22),
  B23 = (1 << 23),
  B24 = (1 << 24),
  B25 = (1 << 25),
  B26 = (1 << 26),
  B27 = (1 << 27),
  B28 = (1 << 28),
  B29 = (1 << 29),
  B30 = (1 << 30),
  B31 = (1 << 31),
};

#define OP(op) op
#define OP_W(op) op##_w
#define OP_X(op) op##_x
#define OP_S(op) op##_s
#define OP_D(op) op##_d
#define OP_Q(op) op##_q

#define OPT(op, attribute) op##_##attribute
#define OPT_W(op, attribute) op##_w_##attribute
#define OPT_X(op, attribute) op##_x_##attribute
#define OPT_S(op, attribute) op##_s_##attribute
#define OPT_D(op, attribute) op##_d_##attribute
#define OPT_Q(op, attribute) op##_q_##attribute

// Unconditional branch.
enum UnconditionalBranchOp {
  UnconditionalBranchFixed = 0x14000000,
  UnconditionalBranchFMask = 0x7C000000,
  UnconditionalBranchMask  = 0xFC000000,
  B                        = UnconditionalBranchFixed | 0x00000000,
  BL                       = UnconditionalBranchFixed | 0x80000000
};

// Unconditional branch to register.
enum UnconditionalBranchToRegisterOp {
  UnconditionalBranchToRegisterFixed = 0xD6000000,
  UnconditionalBranchToRegisterFMask = 0xFE000000,
  UnconditionalBranchToRegisterMask  = 0xFFFFFC1F,
  BR                                 = UnconditionalBranchToRegisterFixed | 0x001F0000,
  BLR                                = UnconditionalBranchToRegisterFixed | 0x003F0000,
  RET                                = UnconditionalBranchToRegisterFixed | 0x005F0000
};

enum LoadRegLiteralOp {
  LoadRegLiteralFixed = 0x18000000,
  LoadRegLiteralMask  = 0xFF000000,

#define LoadRegLiteral_ENCODE(op, opc, V) op | LFT(opc, 30) | LFT(V, 26)
  OPT_W(LDR, literal) = LoadRegLiteral_ENCODE(LoadRegLiteralFixed, 0b00, 0),
  OPT_S(LDR, literal) = LoadRegLiteral_ENCODE(LoadRegLiteralFixed, 0b00, 1),
  OPT_X(LDR, literal) = LoadRegLiteral_ENCODE(LoadRegLiteralFixed, 0b01, 0),
  OPT_D(LDR, literal) = LoadRegLiteral_ENCODE(LoadRegLiteralFixed, 0b01, 1),
  OPT(LDRSW, literal) = LoadRegLiteral_ENCODE(LoadRegLiteralFixed, 0b10, 0),
  OPT_Q(LDR, literal) = LoadRegLiteral_ENCODE(LoadRegLiteralFixed, 0b10, 1),
  OPT(PRFM, literal)  = LoadRegLiteral_ENCODE(LoadRegLiteralFixed, 0b11, 0),
};

// clang-format off

#define LOAD_STORE_OP_LIST(V)   \
  V(OP_W(STRB),  0x00000000),   \
  V(OP_W(STRH),  0x40000000),   \
  V(OP_W(STR),   0x80000000),   \
  V(OP_X(STR),   0xC0000000),   \
  V(OP_W(LDRB),  0x00400000),   \
  V(OP_W(LDRH),  0x40400000),   \
  V(OP_W(LDR),   0x80400000),   \
  V(OP_X(LDR),   0xC0400000),   \
  V(OP_X(LDRSB), 0x00800000),   \
  V(OP_X(LDRSH), 0x40800000),   \
  V(OP_X(LDRSW), 0x80800000),   \
  V(OP_W(LDRSB), 0x00C00000),   \
  V(OP_W(LDRSH), 0x40C00000),   \
  V(OP_B(STR),   0x04000000),   \
  V(OP_H(STR),   0x44000000),   \
  V(OP_S(STR),   0x84000000),   \
  V(OP_D(STR),   0xC4000000),   \
  V(OP_Q(STR),   0x04800000),   \
  V(OP_B(LDR),   0x04400000),   \
  V(OP_H(LDR),   0x44400000),   \
  V(OP_S(LDR),   0x84400000),   \
  V(OP_D(LDR),   0xC4400000),   \
  V(OP_Q(LDR),   0x04C00000)

// clang-format on

// Load/store (post, pre, offset and unsigned.)
enum LoadStoreOp {
  LoadStoreMask = 0xC4C00000,
#define LOAD_STORE(opname, opcode) opname = opcode
  LOAD_STORE_OP_LIST(LOAD_STORE),
#undef LOAD_STORE
  PRFM = 0xC0800000
};

// Load/store unsigned offset.
enum LoadStoreUnsignedOffset {
  LoadStoreUnsignedOffsetFixed = 0x39000000,
  LoadStoreUnsignedOffsetMask  = 0xFFC00000,
#define LOAD_STORE_UNSIGNED_OFFSET(opname, opcode) OPT(opname, unsigned) = LoadStoreUnsignedOffsetFixed | D
  LOAD_STORE_OP_LIST(LOAD_STORE_UNSIGNED_OFFSET),
#undef LOAD_STORE_UNSIGNED_OFFSET
  PRFM_unsigned = LoadStoreUnsignedOffsetFixed | PRFM,
};

#endif