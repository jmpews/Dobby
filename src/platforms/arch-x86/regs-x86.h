#ifndef platforms_arch_x86_regs_h
#define platforms_arch_x86_regs_h

#include "zkit.h"

#include "CommonKit/log/log_kit.h"

#include "instructions.h"

typedef enum _X86Reg {
  ZZ_X86_REG_R0 = 0,
} X86Reg;

typedef struct _X86RegInfo {
  int index;
  int meta;
  int width;
  bool is_integer;
} X86RegInfo;

void x86_register_describe(X86Reg reg, X86RegInfo *ri);

#endif