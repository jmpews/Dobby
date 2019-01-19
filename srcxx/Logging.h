#ifndef HOOKZZ_LOGGING_H_
#define HOOKZZ_LOGGING_H_

#include "PlatformInterface/platform.h"

#if ENABLE_COLOR_LOG
#define RED "\x1B[31m"
#define GRN "\x1B[32m"
#define YEL "\x1B[33m"
#define BLU "\x1B[34m"
#define MAG "\x1B[35m"
#define CYN "\x1B[36m"
#define WHT "\x1B[37m"
#define RESET "\x1B[0m"
#else
#define RED ""
#define GRN ""
#define YEL ""
#define BLU ""
#define MAG ""
#define CYN ""
#define WHT ""
#define RESET ""
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef DLOG
#if defined(DEBUG)
#define DLOG(fmt, ...) zz::OSPrint::Print(fmt, __VA_ARGS__)
#else
#define DLOG(fmt, ...)
#endif
#endif

#endif
