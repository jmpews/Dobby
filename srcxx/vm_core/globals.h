#ifndef ZZ_GLOBALS_H_
#define ZZ_GLOBALS_H_

#include "vm_core/macros.h"
#include "vm_core/platform/globals.h"

// Types for native machine words. Guaranteed to be able to hold pointers and
// integers.
typedef intptr_t word;
typedef uintptr_t uword;

#endif