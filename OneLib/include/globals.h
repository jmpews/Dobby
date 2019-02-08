#ifndef GLOBALS_H_
#define GLOBALS_H_

// Types for native machine words. Guaranteed to be able to hold pointers and
// integers.

#include "kernel_or_user.h"

#ifndef __addr_t_defined
#define __addr_t_defined
typedef unsigned long addr_t;
#endif

#ifndef __byte_defined
#define __byte_defined
typedef unsigned char byte;
#endif

#ifndef __uint_defined
#define __uint_defined
typedef unsigned int uint;
#endif

#ifndef __word_defined
#define __word_defined
typedef short word;
#endif

#ifndef __dword_defined
#define __dword_defined
typedef int dword;
#endif

#if defined(_M_X64) || defined(__x86_64__)
#define TARGET_ARCH_X64 1
#elif defined(_M_IX86) || defined(__i386__)
#define TARGET_ARCH_IA32 1
#elif defined(__AARCH64EL__)
#define TARGET_ARCH_ARM64 1
#elif defined(__ARMEL__)
#define TARGET_ARCH_ARM 1
#elif defined(__mips64)
#define TARGET_ARCH_MIPS64 1
#elif defined(__MIPSEB__) || defined(__MIPSEL__)
#define TARGET_ARCH_MIPS 1
#elif defined(_ARCH_PPC)
#define TARGET_ARCH_PPC 1
#else
#error Target architecture was not detected as supported by v8
#endif

#endif