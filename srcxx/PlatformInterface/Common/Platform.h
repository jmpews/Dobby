#ifndef ZZ_PLATFORM_PLATFORM_H_
#define ZZ_PLATFORM_PLATFORM_H_

#include <stdarg.h>

#include "UnifiedInterface/StdMemory.h"

namespace zz {

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

} // namespace zz

#endif
