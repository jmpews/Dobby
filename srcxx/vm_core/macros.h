#ifndef ZZ_MACROS_H_
#define ZZ_MACROS_H_

#include <stdio.h>
#include <stdint.h>

#include "vm_core/logging.h"

#define OFFSETOF(TYPE, ELEMENT) ((size_t) & (((TYPE *)0)->ELEMENT))

typedef char byte;

// globals macro
#define XCHECK(cond) assert(cond)

// left/right shift
#define LFT(a, b, c) ((a & ((1 << b) - 1)) << c)
#define RHT(a, b, c) ((a >> c) & ((1 << b) - 1))

#define ALIGN_FLOOR(address, range) ((uintptr_t)address & ~((uintptr_t)range - 1))
#define ALIGN_CEIL(address, range) (((uintptr_t)address + (uintptr_t)range - 1) & ~((uintptr_t)range - 1))

/* borrow from gdb, refer: binutils-gdb/gdb/arch/arm.h */
#define submask(x) ((1L << ((x) + 1)) - 1)
#define bits(obj, st, fn) (((obj) >> (st)) & submask((fn) - (st)))
#define bit(obj, st) (((obj) >> (st)) & 1)
#define sbits(obj, st, fn) ((long)(bits(obj, st, fn) | ((long)bit(obj, fn) * ~submask(fn - st))))

#endif