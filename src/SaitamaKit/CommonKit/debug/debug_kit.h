#ifndef common_debug_kit_h
#define common_debug_kit_h

#include "debugbreak.h"

#define ZZ_DEBUG_BREAK()                                                                                               \
    do {                                                                                                               \
        debug_break();                                                                                                 \
    } while (0)

#endif