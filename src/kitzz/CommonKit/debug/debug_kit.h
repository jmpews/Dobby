#ifndef commonkit_debug_debug_kit_h
#define commonkit_debug_debug_kit_h

#include "debugbreak.h"
#include "kitzz.h"

#define ZZ_DEBUG_BREAK()                                                                                               \
    do {                                                                                                               \
        if (GLOBAL_DEBUG)                                                                                              \
            debug_break();                                                                                             \
    } while (0)

#endif