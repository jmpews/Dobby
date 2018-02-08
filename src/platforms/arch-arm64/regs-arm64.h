#ifndef platforms_arch_arm64_regs_h
#define platforms_arch_arm64_regs_h

#include "kitzz.h"

#include "CommonKit/log/log_kit.h"

#include "instructions.h"

typedef enum _ZzARM64Reg {
    ZZ_ARM64_REG_X0 = 0,
    ZZ_ARM64_REG_X1,
    ZZ_ARM64_REG_X2,
    ZZ_ARM64_REG_X3,
    ZZ_ARM64_REG_X4,
    ZZ_ARM64_REG_X5,
    ZZ_ARM64_REG_X6,
    ZZ_ARM64_REG_X7,
    ZZ_ARM64_REG_X8,
    ZZ_ARM64_REG_X9,
    ZZ_ARM64_REG_X10,
    ZZ_ARM64_REG_X11,
    ZZ_ARM64_REG_X12,
    ZZ_ARM64_REG_X13,
    ZZ_ARM64_REG_X14,
    ZZ_ARM64_REG_X15,
    ZZ_ARM64_REG_X16,
    ZZ_ARM64_REG_X17,
    ZZ_ARM64_REG_X18,
    ZZ_ARM64_REG_X19,
    ZZ_ARM64_REG_X20,
    ZZ_ARM64_REG_X21,
    ZZ_ARM64_REG_X22,
    ZZ_ARM64_REG_X23,
    ZZ_ARM64_REG_X24,
    ZZ_ARM64_REG_X25,
    ZZ_ARM64_REG_X26,
    ZZ_ARM64_REG_X27,
    ZZ_ARM64_REG_X28,
    ZZ_ARM64_REG_X29,
    ZZ_ARM64_REG_X30,
    ZZ_ARM64_REG_X31,
    ZZ_ARM64_REG_FP = ZZ_ARM64_REG_X29,
    ZZ_ARM64_REG_LR = ZZ_ARM64_REG_X30,
    ZZ_ARM64_REG_SP = ZZ_ARM64_REG_X31
} ZzARM64Reg;

typedef struct _ZzARM64RegInfo {
    int index;
    int meta;
    int width;
    bool is_integer;
} ZzARM64RegInfo;

void zz_arm64_register_describe(ZzARM64Reg reg, ZzARM64RegInfo *ri);

#endif