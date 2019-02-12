#ifndef ARCH_X64_CONSTANTS_H_
#define ARCH_X64_CONSTANTS_H_

enum ScaleFactor {
  TIMES_1              = 0,
  TIMES_2              = 1,
  TIMES_4              = 2,
  TIMES_8              = 3,
  TIMES_16             = 4,
  TIMES_HALF_WORD_SIZE = sizeof(void *) / 2 - 1
};

enum RexBits { REX_NONE = 0, REX_B = 1 << 0, REX_X = 1 << 1, REX_R = 1 << 2, REX_W = 1 << 3, REX_PREFIX = 1 << 6 };

#endif