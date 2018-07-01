#ifndef core_h
#define core_h

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "logging.h"
#include "std_kit/std_kit.h"
#include "std_kit/std_macros.h"

/* define a macro to make abbreviation */
#define cclass(class, member) class##_##member
#define cxxclass(class, member) class##member

/* indicate this API's implemention is System dependent */
#define PLATFORM_API

/* indicate this API's implemention is Architecture dependent */
#define ARCH_API

/* indicate this API's implemention is public */
#define PUBLIC_API

/* hidden funtion */
#define VIS_HIDDEN __attribute__((visibility("hidden")))
#endif