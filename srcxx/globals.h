
#ifndef ZZ_GLOBALS_H
#define ZZ_GLOBALS_H

#include <stdint.h>

#if defined(_WIN32)
#define PUBLIC
#else
#define PUBLIC __attribute__((visibility("default")))
#endif

#include "logging/logging.h"

#endif
