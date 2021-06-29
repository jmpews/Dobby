#pragma once

#ifdef __cplusplus
#if defined(BUILDING_KERNEL)
#include "ArxContainer.h"
#define std arx
#else
#include <vector>
#include <map>
#endif
#endif

#if defined(BUILDING_KERNEL)
#else
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#endif

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <syslog.h>
#endif