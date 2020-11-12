#include <stdio.h>
#include <stdint.h>

#include "logging/logging.h"

enum SegmentPrefix {
  kCs = 0x2e,
  kSs = 0x36,
  kDs = 0x3e,
  kEs = 0x26,
  kFs = 0x64,
  kGs = 0x65,
};

bool supports_rex_ = false;

void DecodeInstruction(uint8_t *instr) {
  bool    have_prefixes = true;
  uint8_t prefix[4]     = {0, 0, 0, 0};

  // decode legacy prefix
  do {
    switch (*instr) {
      // Group 1 - lock and repeat prefixes:
    case 0xF0:
    case 0xF2:
    case 0xF3:
      prefix[0] = *instr;
      break;
      // Group 2 - segment override prefixes:
    case kCs:
    case kSs:
    case kDs:
    case kEs:
    case kFs:
    case kGs:
      prefix[1] = *instr;
      break;
      // Group 3 - operand size override:
    case 0x66:
      prefix[2] = *instr;
      break;
      // Group 4 - address size override:
    case 0x67:
      prefix[3] = *instr;
      break;
    default:
      have_prefixes = false;
      break;
    }
    if (have_prefixes) {
      instr++;
    }
  } while (have_prefixes);

  // x64 rex
  uint8_t rex = (supports_rex_ && (*instr >= 0x40) && (*instr <= 0x4F)) ? *instr : 0;
  if (rex != 0) {
    instr++;
  }

  bool has_modrm     = false;
  bool reg_is_opcode = false;

  size_t immediate_bytes = 0;

#define OpEn_MR                                                                                                        \
  do {                                                                                                                 \
    has_modrm = true;                                                                                                  \
  } while (0);                                                                                                         \
  break;

#define OpEn_RM                                                                                                        \
  do {                                                                                                                 \
    has_modrm = true;                                                                                                  \
  } while (0);                                                                                                         \
  break;

#define OpEn_I(immediate_size)                                                                                         \
  do {                                                                                                                 \
    immediate_bytes = immediate_size;                                                                                  \
  } while (0);                                                                                                         \
  break;

#define UnImplOpcode                                                                                                   \
  do {                                                                                                                 \
    DLOG(0, "opcode unreachable");                                                                                     \
  } while (0);                                                                                                         \
  break;

  typedef enum {
    MR,
  } OpEnTy;

  // decode opcode
  switch (*instr) {
  case 0x00:
    OpEn_MR;
  case 0x01:
    OpEn_MR;
  case 0x02:
    OpEn_RM;
  case 0x03:
    OpEn_RM;
  case 0x04:
    OpEn_I(8);
  case 0x05:
    OpEn_I(16 | 32);

  case 0x06:
  case 0x07:
    UnImplOpcode;

  case 0x08:
    OpEn_MR;
  case 0x09:
    OpEn_MR;
  case 0x0a:
    OpEn_RM;
  case 0x0b:
    OpEn_RM;
  case 0x0c:
    OpEn_I(8);
  case 0x0d:
    OpEn_I(16 | 32);

  case 0x0e:
  case 0x0f:
    UnImplOpcode;

  case 0x10:
    OpEn_MR;
  case 0x11:
    OpEn_MR;
  case 0x12:
    OpEn_RM;
  case 0x13:
    OpEn_RM;
  case 0x14:
    OpEn_I(8);
  case 0x15:
    OpEn_I(16 | 32);

  case 0x16:
  case 0x17:
    UnImplOpcode;

  case 0x18:
    OpEn_MR;
  case 0x19:
    OpEn_MR;
  case 0x1a:
    OpEn_RM;
  case 0x1b:
    OpEn_RM;
  case 0x1c:
    OpEn_I(8);
  case 0x1d:
    OpEn_I(16 | 32);

  case 0x1e:
  case 0x1f:
    UnImplOpcode;

  case 0x20:
    OpEn_MR;
  case 0x21:
    OpEn_MR;
  case 0x22:
    OpEn_RM;
  case 0x23:
    OpEn_RM;
  case 0x24:
    OpEn_I(8);
  case 0x25:
    OpEn_I(16 | 32);

  case 0x26:
  case 0x27:
    UnImplOpcode;

  case 0x28:
    OpEn_MR;
  case 0x29:
    OpEn_MR;
  case 0x2a:
    OpEn_RM;
  case 0x2b:
    OpEn_RM;
  case 0x2c:
    OpEn_I(8);
  case 0x2d:
    OpEn_I(16 | 32);

  case 0x2e:
  case 0x2f:
    UnImplOpcode;

  case 0x30:
    OpEn_MR;
  case 0x31:
    OpEn_MR;
  case 0x32:
    OpEn_RM;
  case 0x33:
    OpEn_RM;
  case 0x34:
    OpEn_I(8);
  case 0x35:
    OpEn_I(16 | 32);

  case 0x36:
  case 0x37:
    UnImplOpcode;

  case 0x38:
    OpEn_MR;
  case 0x39:
    OpEn_MR;
  case 0x3a:
    OpEn_RM;
  case 0x3b:
    OpEn_RM;
  case 0x3c:
    OpEn_I(8);
  case 0x3d:
    OpEn_I(16 | 32);

  case 0x40:
  case 0x41:
  case 0x42:
  case 0x43:
  case 0x44:
  case 0x45:
  case 0x46:
  case 0x47:
  case 0x48:
  case 0x49:
  case 0x4a:
  case 0x4b:
  case 0x4c:
  case 0x4d:
  case 0x4e:
  case 0x4f:
    UnImplOpcode;
  }
}
