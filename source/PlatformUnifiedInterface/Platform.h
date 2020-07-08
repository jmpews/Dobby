#ifndef PLATFORM_INTERFACE_COMMON_PLATFORM_H
#define PLATFORM_INTERFACE_COMMON_PLATFORM_H

#include <stdarg.h>

#include "StdMemory.h"

class OSMemory {
public:
  static int PageSize();

  static void *Allocate(void *address, int size, MemoryPermission access);

  static bool Free(void *address, const int size);

  static bool Release(void *address, int size);

  static bool SetPermissions(void *address, int size, MemoryPermission access);
};

class OSPrint {
public:
  // Print output to console. This is mostly used for debugging output.
  // On platforms that has standard terminal output, the output
  // should go to stdout.
  static void Print(const char *format, ...);

  static void VPrint(const char *format, va_list args);

  // Print error output to console. This is mostly used for error message
  // output. On platforms that has standard terminal output, the output
  // should go to stderr.
  static void PrintError(const char *format, ...);

  static void VPrintError(const char *format, va_list args);
};

#endif
