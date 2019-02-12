#ifndef MACROS_H_
#define MACROS_H_

#include "globals.h"

// offset of struct member
#define OFFSETOF(TYPE, ELEMENT) ((size_t) & (((TYPE *)0)->ELEMENT))

// assert
#define ASSERT(X) ((void)0)

// left/right shift
#define LFT(a, b, c) ((a & ((1 << b) - 1)) << c)
#define RHT(a, b, c) ((a >> c) & ((1 << b) - 1))

// align
#ifndef ALIGN
#define ALIGN ALIGN_FLOOR
#endif
#define ALIGN_FLOOR(address, range) ((addr_t)address & ~((addr_t)range - 1))
#define ALIGN_CEIL(address, range) (((addr_t)address + (addr_t)range - 1) & ~((addr_t)range - 1))

// borrow from gdb, refer: binutils-gdb/gdb/arch/arm.h
#define submask(x) ((1L << ((x) + 1)) - 1)
#define bits(obj, st, fn) (((obj) >> (st)) & submask((fn) - (st)))
#define bit(obj, st) (((obj) >> (st)) & 1)
#define sbits(obj, st, fn) ((long)(bits(obj, st, fn) | ((long)bit(obj, fn) * ~submask(fn - st))))

// definition to expand macro then apply to pragma message
// #pragma message(VAR_NAME_VALUE(HOST_OS_IOS))
#define VALUE_TO_STRING(x) #x
#define VALUE(x) VALUE_TO_STRING(x)
#define VAR_NAME_VALUE(var) #var "=" VALUE(var)

// format print
#define PRIxPTR PTR_PREFIX "x"
#if defined(__arm64__) || defined(__aarch64__)
#define PTR_PREFIX "l"
#elif defined(__arm__)
#define PTR_PREFIX ""
#elif defined(_M_X64) || defined(__x86_64__)
#define PTR_PREFIX "l"
#else
#error "unsupported architecture"
#endif

// deprecated declared
#if defined(__GNUC__) || defined(__clang__)
#define DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define DEPRECATED __declspec(deprecated)
#else
#pragma message("WARNING: You need to implement DEPRECATED for this compiler")
#define DEPRECATED
#endif

// export method
#if defined(_WIN32)
#define PUBLIC
#else
#define PUBLIC __attribute__((visibility("default")))
#endif

#endif
